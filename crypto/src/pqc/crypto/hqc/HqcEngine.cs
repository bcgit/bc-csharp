using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class HqcEngine
    {
        internal const int SharedSecretBytes = 32;
        private const int SaltBytes = 16;
        private const int SeedBytes = 40;

        private int n;
        private int n1;
        private int n2;
        private int k;
        private int delta;
        private int w;
        private int wr;
        private int we;
        private int g;
        private int fft;
        private int mulParam;

        private byte G_FCT_DOMAIN = 3;
        private byte K_FCT_DOMAIN = 4;

        private int N_BYTE;
        private int n1n2;
        private int N_BYTE_64;
        private int K_BYTE;
        private int N1N2_BYTE_64;
        private int N1N2_BYTE;

        private readonly int[] m_generatorPoly;
        private readonly GF2PolynomialCalculator m_gf;
        private readonly int m_rejectionThreshold;
        private readonly int m_cipherTextBytes;

        internal HqcEngine(int n, int n1, int n2, int k, int g, int delta, int w, int wr, int we, int fft, int[] generatorPoly)
        {
            this.n = n;
            this.k = k;
            this.delta = delta;
            this.w = w;
            this.wr = wr;
            this.we = we;
            this.n1 = n1;
            this.n2 = n2;
            this.n1n2 = n1 * n2;
            this.g = g;
            this.fft = fft;

            mulParam = (n2 + 127) / 128;
            N_BYTE = Utils.GetByteSizeFromBitSize(n);
            K_BYTE = k;
            N_BYTE_64 = Utils.GetByte64SizeFromBitSize(n);
            N1N2_BYTE_64 = Utils.GetByte64SizeFromBitSize(n1 * n2);
            N1N2_BYTE = Utils.GetByteSizeFromBitSize(n1 * n2);

            m_generatorPoly = generatorPoly;
            m_gf = new GF2PolynomialCalculator(n);
            m_rejectionThreshold = ((1 << 24) / n) * n;
            m_cipherTextBytes = N_BYTE + N1N2_BYTE + 16;
        }

        internal int CipherTextBytes => m_cipherTextBytes;

        /**
         * Generate key pairs
         * - Secret key : (x,y)
         * - Public key: (h,s)
         *  @param pk     output pk = (publicSeed||s)
         *
         **/
        public void GenKeyPair(byte[] pk, byte[] sk, byte[] seed)
        {
            // Randomly generate seeds for secret keys and public keys
            byte[] secretKeySeed = new byte[SeedBytes];
            byte[] sigma = new byte[K_BYTE];

            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.RandomGeneratorInit(seed, null, seed.Length, 0);
            randomGenerator.Squeeze(secretKeySeed, 40);
            randomGenerator.Squeeze(sigma, K_BYTE);

            // 1. Randomly generate secret keys x, y
            HqcKeccakRandomGenerator secretKeySeedExpander = new HqcKeccakRandomGenerator(256);
            secretKeySeedExpander.SeedExpanderInit(secretKeySeed, secretKeySeed.Length);

            ulong[] xLongBytes = m_gf.Create();
            ulong[] yLongBytes = m_gf.Create();

            GenerateRandomFixedWeight(yLongBytes, secretKeySeedExpander, w);
            GenerateRandomFixedWeight(xLongBytes, secretKeySeedExpander, w);

            // 2. Randomly generate h
            byte[] publicKeySeed = new byte[SeedBytes];
            randomGenerator.Squeeze(publicKeySeed, 40);

            HqcKeccakRandomGenerator randomPublic = new HqcKeccakRandomGenerator(256);
            randomPublic.SeedExpanderInit(publicKeySeed, publicKeySeed.Length);

            ulong[] hLongBytes = m_gf.Create();
            GeneratePublicKeyH(hLongBytes, randomPublic);

            // 3. Compute s
            ulong[] s = m_gf.Create();
            m_gf.Mul(yLongBytes, hLongBytes, s);
            m_gf.AddTo(xLongBytes, s);
            byte[] sBytes = new byte[N_BYTE];
            Utils.FromUInt64ArrayToByteArray(sBytes, s);

            byte[] tmpPk = Arrays.Concatenate(publicKeySeed, sBytes);
            byte[] tmpSk = Arrays.ConcatenateAll(secretKeySeed, sigma, tmpPk);

            Array.Copy(tmpPk, 0, pk, 0, tmpPk.Length);
            Array.Copy(tmpSk, 0, sk, 0, tmpSk.Length);
        }

        /**
         * HQC Encapsulation
         * - Input: pk, seed
         * - Output: c = (u,v,d), K
         *
         * @param u    u
         * @param v    v
         * @param d    d
         * @param K    session key
         * @param pk   public key
         * @param seed seed
         **/
        public void Encaps(byte[] u, byte[] v, byte[] K, byte[] pk, byte[] seed, byte[] salt)
        {
            // 1. Randomly generate m
            byte[] m = new byte[K_BYTE];

            // TODO: no way to gen m without seed and gen skseed, pkseed. In reference implementation they use the same
            byte[] secretKeySeed = new byte[SeedBytes];
            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.RandomGeneratorInit(seed, null, seed.Length, 0);
            randomGenerator.Squeeze(secretKeySeed, 40);

            byte[] sigma = new byte[K_BYTE];
            randomGenerator.Squeeze(sigma, K_BYTE);

            byte[] publicKeySeed = new byte[SeedBytes];
            randomGenerator.Squeeze(publicKeySeed, 40);

            // gen m
            randomGenerator.Squeeze(m, K_BYTE);

            // 2. Generate theta
            byte[] theta = new byte[64];
            byte[] tmp = new byte[K_BYTE + (SaltBytes * 2) + SaltBytes];
            randomGenerator.Squeeze(salt, SaltBytes);

            Array.Copy(m, 0, tmp, 0, m.Length);
            Array.Copy(pk, 0, tmp, K_BYTE, SaltBytes * 2);
            Array.Copy(salt, 0, tmp, K_BYTE + (SaltBytes * 2), SaltBytes);
            HqcKeccakRandomGenerator shakeDigest = new HqcKeccakRandomGenerator(256);
            shakeDigest.SHAKE256_512_ds(theta, tmp, tmp.Length, new[] { G_FCT_DOMAIN });

            // 3. Generate ciphertext c = (u,v)
            // Extract public keys
            ulong[] h = m_gf.Create();
            byte[] s = new byte[N_BYTE];
            ExtractPublicKeys(h, s, pk);

            ulong[] vTmp = new ulong[N1N2_BYTE_64];
            Encrypt(u, vTmp, h, s, m, theta);
            Utils.FromUInt64ArrayToByteArray(v, vTmp);

            // 5. Compute session key K
            byte[] hashInputK = Arrays.ConcatenateAll(m, u, v);
            shakeDigest.SHAKE256_512_ds(K, hashInputK, hashInputK.Length, new[] { K_FCT_DOMAIN });
        }

        /**
         * HQC Decapsulation
         * - Input: ct, sk
         * - Output: ss
         *
         * @param ss session key
         * @param ct ciphertext
         * @param sk secret key
         * @return 0 if decapsulation is successful, -1 otherwise
         **/
        public int Decaps(byte[] ss, byte[] ct, byte[] sk)
        {
            //Extract Y and Public Keys from sk
            ulong[] x = m_gf.Create();
            ulong[] y = m_gf.Create();
            byte[] pk = new byte[40 + N_BYTE];
            byte[] sigma = new byte[K_BYTE];
            ExtractKeysFromSecretKeys(y, sigma, pk, sk);

            // Extract u, v, d from ciphertext
            byte[] u = new byte[N_BYTE];
            byte[] v = new byte[N1N2_BYTE];
            byte[] salt = new byte[SaltBytes];
            ExtractCiphertexts(u, v, salt, ct);

            // 1. Decrypt -> m'
            byte[] mPrimeBytes = new byte[k];
            Decrypt(mPrimeBytes, mPrimeBytes, sigma, u, v, y);

            // 2. Compute theta'
            byte[] theta = new byte[64];
            byte[] tmp = new byte[K_BYTE + (SaltBytes * 2) + SaltBytes];
            Array.Copy(mPrimeBytes, 0, tmp, 0, mPrimeBytes.Length);
            Array.Copy(pk, 0, tmp, K_BYTE, SaltBytes * 2);
            Array.Copy(salt, 0, tmp, K_BYTE + (SaltBytes * 2), SaltBytes);
            HqcKeccakRandomGenerator shakeDigest = new HqcKeccakRandomGenerator(256);
            shakeDigest.SHAKE256_512_ds(theta, tmp, tmp.Length, new[] { G_FCT_DOMAIN });

            // 3. Compute c' = Enc(pk, m', theta')
            // Extract public keys
            ulong[] h = m_gf.Create();
            byte[] s = new byte[N_BYTE];
            ExtractPublicKeys(h, s, pk);

            byte[] u2Bytes = new byte[N_BYTE];
            byte[] v2Bytes = new byte[N1N2_BYTE];
            ulong[] vTmp = new ulong[N1N2_BYTE_64];
            Encrypt(u2Bytes, vTmp, h, s, mPrimeBytes, theta);
            Utils.FromUInt64ArrayToByteArray(v2Bytes, vTmp);

            // 5. Compute session key KPrime
            byte[] hashInputK = new byte[K_BYTE + N_BYTE + N1N2_BYTE];

            int result = 0;

            // Compare u, v, d
            if (!Arrays.FixedTimeEquals(u, u2Bytes))
            {
                result = 1;
            }

            if (!Arrays.FixedTimeEquals(v, v2Bytes))
            {
                result = 1;
            }

            result -= 1;

            for (int i = 0; i < K_BYTE; i++)
            {
                hashInputK[i] = (byte)((mPrimeBytes[i] & result) ^ (sigma[i] & ~result));
            }

            Array.Copy(u, 0, hashInputK, K_BYTE, N_BYTE);
            Array.Copy(v, 0, hashInputK, K_BYTE + N_BYTE, N1N2_BYTE);
            shakeDigest.SHAKE256_512_ds(ss, hashInputK, hashInputK.Length, new[] { K_FCT_DOMAIN });
            return -result;;
        }

        /**
         * HQC Encryption
         * - Input: (h,s, m)
         * - Output: (u,v) = c
         *
         * @param h public key
         * @param s public key
         * @param m message
         * @param u ciphertext
         * @param v ciphertext
         **/
        private void Encrypt(byte[] u, ulong[] v, ulong[] h, byte[] s, byte[] m, byte[] theta)
        {
            // Randomly generate e, r1, r2
            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.SeedExpanderInit(theta, SeedBytes);
            ulong[] e = m_gf.Create();
            ulong[] r1 = m_gf.Create();
            ulong[] r2 = m_gf.Create();
            GenerateRandomFixedWeight(r2, randomGenerator, wr);
            GenerateRandomFixedWeight(e, randomGenerator, we);
            GenerateRandomFixedWeight(r1, randomGenerator, wr);

            // Calculate u
            ulong[] uLong = m_gf.Create();
            m_gf.Mul(r2, h, uLong);
            m_gf.AddTo(r1, uLong);
            Utils.FromUInt64ArrayToByteArray(u, uLong);

            // Calculate v
            // encode m
            byte[] res = new byte[n1];
            ulong[] vLong = new ulong[N1N2_BYTE_64];
            ulong[] tmpVLong = m_gf.Create();
            ReedSolomon.Encode(res, m, K_BYTE * 8, n1, k, g, m_generatorPoly);
            ReedMuller.Encode(vLong, res, n1, mulParam);
            Array.Copy(vLong, 0, tmpVLong, 0, vLong.Length);

            //Compute v
            ulong[] sLong = m_gf.Create();
            Utils.FromByteArrayToUInt64Array(sLong, s);

            ulong[] tmpLong = m_gf.Create();
            m_gf.Mul(r2, sLong, tmpLong);
            m_gf.AddTo(tmpVLong, tmpLong);
            m_gf.AddTo(e, tmpLong);

            Utils.ResizeArray(v, n1n2, tmpLong, n, N1N2_BYTE_64, N1N2_BYTE_64);
        }

        private void Decrypt(byte[] output, byte[] m, byte[] sigma, byte[] u, byte[] v, ulong[] y)
        {
            ulong[] uLongs = m_gf.Create();
            Utils.FromByteArrayToUInt64Array(uLongs, u);

            ulong[] vLongs = new ulong[N1N2_BYTE_64];
            Utils.FromByteArrayToUInt64Array(vLongs, v);

            ulong[] tmpV = m_gf.Create();
            Array.Copy(vLongs, 0, tmpV, 0, vLongs.Length);

            ulong[] tmpLong = m_gf.Create();
            m_gf.Mul(y, uLongs, tmpLong);
            m_gf.AddTo(tmpV, tmpLong);

            // Decode res
            byte[] tmp = new byte[n1];
            ReedMuller.Decode(tmp, tmpLong, n1, mulParam);
            ReedSolomon.Decode(m, tmp, n1, fft, delta, k, g);

            Array.Copy(m, 0, output, 0, output.Length);
        }

        private void GenerateRandomFixedWeight(ulong[] output, HqcKeccakRandomGenerator random, int weight)
        {
            uint[] rand_u32 = new uint[wr];
            byte[] rand_bytes = new byte[wr * 4];
            int[] support = new int[wr];
            int[] index_tab = new int[wr];
            long[] bit_tab = new long[wr];

            random.ExpandSeed(rand_bytes, 4 * weight);
            Pack.LE_To_UInt32(rand_bytes, 0, rand_u32, 0, rand_u32.Length);

            for (int i = 0; i < weight; i++)
            {
                support[i] = (int)(i + ((rand_u32[i] & 0xFFFFFFFFL) % (n - i)));
            }

            for (int i = weight - 1; i >= 0; i--)
            {
                int mask = 0;
                for (int j = i + 1; j < weight; j++)
                {
                    if (support[j] == support[i])
                    {
                        mask = -1;
                    }
                }

                support[i] = (mask & i) ^ (~mask & support[i]);
            }

            for (int i = 0; i < weight; i++)
            {
                index_tab[i] = (int)((uint)support[i] >> 6);
                int pos = support[i] & 63;
                bit_tab[i] = 1L << pos;
            }

            for (int i = 0; i < N_BYTE_64; i++)
            {
                ulong val = output[i];
                for (int j = 0; j < weight; j++)
                {
                    long tmp = i ^ index_tab[j];
                    long mask = (tmp | -tmp) >> 63;
                    val |= (ulong)(bit_tab[j] & ~mask);
                }
                output[i] = val;
            }
        }

        void GeneratePublicKeyH(ulong[] output, HqcKeccakRandomGenerator random)
        {
            byte[] randBytes = new byte[N_BYTE];
            random.ExpandSeed(randBytes, N_BYTE);

            Utils.FromByteArrayToUInt64Array(output, randBytes);
            output[N_BYTE_64 - 1] &= (1UL << (n & 63)) - 1UL;
        }

        private void ExtractPublicKeys(ulong[] h, byte[] s, byte[] pk)
        {
            byte[] publicKeySeed = new byte[SeedBytes];
            Array.Copy(pk, 0, publicKeySeed, 0, publicKeySeed.Length);

            HqcKeccakRandomGenerator randomPublic = new HqcKeccakRandomGenerator(256);
            randomPublic.SeedExpanderInit(publicKeySeed, publicKeySeed.Length);

            GeneratePublicKeyH(h, randomPublic);

            Array.Copy(pk, 40, s, 0, s.Length);
        }

        private void ExtractKeysFromSecretKeys(ulong[] y, byte[] sigma, byte[] pk, byte[] sk)
        {
            byte[] secretKeySeed = new byte[SeedBytes];
            Array.Copy(sk, 0, secretKeySeed, 0, secretKeySeed.Length);
            Array.Copy(sk, SeedBytes, sigma, 0, K_BYTE);

            // Randomly generate secret keys x, y
            HqcKeccakRandomGenerator secretKeySeedExpander = new HqcKeccakRandomGenerator(256);
            secretKeySeedExpander.SeedExpanderInit(secretKeySeed, secretKeySeed.Length);
            
            GenerateRandomFixedWeight(y, secretKeySeedExpander, w);

            Array.Copy(sk, SeedBytes + K_BYTE, pk, 0, pk.Length);
        }

        private static void ExtractCiphertexts(byte[] u, byte[] v, byte[] salt, byte[] ct)
        {
            Array.Copy(ct, 0, u, 0, u.Length);
            Array.Copy(ct, u.Length, v, 0, v.Length);
            Array.Copy(ct, u.Length + v.Length, salt, 0, salt.Length);
        }
    }
}
