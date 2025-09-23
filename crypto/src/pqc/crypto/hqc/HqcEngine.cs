using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class HqcEngine
    {
        private int n;
        private int n1;
        private int n2;
        private int k;
        private int delta;
        private int w;
        private int wr;
        private int we;
        private int g;
        private int rejectionThreshold;
        private int fft;
        private int mulParam;

        private int SEED_SIZE = 40;
        private byte G_FCT_DOMAIN = 3;
        private byte K_FCT_DOMAIN = 4;

        private int N_BYTE;
        private int n1n2;
        private int N_BYTE_64;
        private int K_BYTE;
        private int K_BYTE_64;
        private int N1_BYTE_64;
        private int N1N2_BYTE_64;
        private int N1N2_BYTE;
        private int N1_BYTE;
        
        //private int GF_POLY_WT  = 5;
        //private int GF_POLY_M2 = 4;
        private int SALT_SIZE_BYTES = 16;
        //private int SALT_SIZE_64 = 2;

        private int[] generatorPoly;

        private ulong RED_MASK;
        private GF2PolynomialCalculator gfCalculator;

        public HqcEngine(int n, int n1, int n2, int k, int g, int delta, int w, int wr, int we, int rejectionThreshold, int fft, int[] generatorPoly)
        {
            this.n = n;
            this.k = k;
            this.delta = delta;
            this.w = w;
            this.wr = wr;
            this.we = we;
            this.n1 = n1;
            this.n2 = n2;
            n1n2 = n1 * n2;
            this.generatorPoly = generatorPoly;
            this.g = g;
            this.rejectionThreshold = rejectionThreshold;
            this.fft = fft;

            mulParam = (n2 + 127) / 128;
            N_BYTE = Utils.GetByteSizeFromBitSize(n);
            K_BYTE = k;
            N_BYTE_64 = Utils.GetByte64SizeFromBitSize(n);
            K_BYTE_64 = Utils.GetByteSizeFromBitSize(k);
            N1_BYTE_64 = Utils.GetByteSizeFromBitSize(n1);
            N1N2_BYTE_64 = Utils.GetByte64SizeFromBitSize(n1 * n2);
            N1N2_BYTE = Utils.GetByteSizeFromBitSize(n1 * n2);
            N1_BYTE = Utils.GetByteSizeFromBitSize(n1);
            
            RED_MASK = ((1UL << (n % 64)) - 1);

            gfCalculator = new GF2PolynomialCalculator(N_BYTE_64, n, RED_MASK);
        }

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
            byte[] secretKeySeed = new byte[SEED_SIZE];
            byte[] sigma = new byte[K_BYTE];

            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.RandomGeneratorInit(seed, null, seed.Length, 0);
            randomGenerator.Squeeze(secretKeySeed, 40);
            randomGenerator.Squeeze(sigma, K_BYTE);

            // 1. Randomly generate secret keys x, y
            HqcKeccakRandomGenerator secretKeySeedExpander = new HqcKeccakRandomGenerator(256);
            secretKeySeedExpander.SeedExpanderInit(secretKeySeed, secretKeySeed.Length);

            long[] xLongBytes = new long[N_BYTE_64];
            long[] yLongBytes = new long[N_BYTE_64];

            GenerateRandomFixedWeight(yLongBytes, secretKeySeedExpander, w);
            GenerateRandomFixedWeight(xLongBytes, secretKeySeedExpander, w);

            // 2. Randomly generate h
            byte[] publicKeySeed = new byte[SEED_SIZE];
            randomGenerator.Squeeze(publicKeySeed, 40);

            HqcKeccakRandomGenerator randomPublic = new HqcKeccakRandomGenerator(256);
            randomPublic.SeedExpanderInit(publicKeySeed, publicKeySeed.Length);

            long[] hLongBytes = new long[N_BYTE_64];
            GeneratePublicKeyH(hLongBytes, randomPublic);

            // 3. Compute s
            long[] s = new long[N_BYTE_64];
            gfCalculator.MultLongs(s, yLongBytes, hLongBytes);
            GF2PolynomialCalculator.AddLongs(s, s, xLongBytes);
            byte[] sBytes = new byte[N_BYTE];
            Utils.FromLongArrayToByteArray(sBytes, s);

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
            byte[] secretKeySeed = new byte[SEED_SIZE];
            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.RandomGeneratorInit(seed, null, seed.Length, 0);
            randomGenerator.Squeeze(secretKeySeed, 40);

            byte[] sigma = new byte[K_BYTE];
            randomGenerator.Squeeze(sigma, K_BYTE);

            byte[] publicKeySeed = new byte[SEED_SIZE];
            randomGenerator.Squeeze(publicKeySeed, 40);

            // gen m
            randomGenerator.Squeeze(m, K_BYTE);

            // 2. Generate theta
            byte[] theta = new byte[64];
            byte[] tmp = new byte[K_BYTE + (SALT_SIZE_BYTES * 2) + SALT_SIZE_BYTES];
            randomGenerator.Squeeze(salt, SALT_SIZE_BYTES);

            Array.Copy(m, 0, tmp, 0, m.Length);
            Array.Copy(pk, 0, tmp, K_BYTE, SALT_SIZE_BYTES * 2);
            Array.Copy(salt, 0, tmp, K_BYTE + (SALT_SIZE_BYTES * 2), SALT_SIZE_BYTES);
            HqcKeccakRandomGenerator shakeDigest = new HqcKeccakRandomGenerator(256);
            shakeDigest.SHAKE256_512_ds(theta, tmp, tmp.Length, new[] { G_FCT_DOMAIN });

            // 3. Generate ciphertext c = (u,v)
            // Extract public keys
            long[] h = new long[N_BYTE_64];
            byte[] s = new byte[N_BYTE];
            ExtractPublicKeys(h, s, pk);

            long[] vTmp = new long[N1N2_BYTE_64];
            Encrypt(u, vTmp, h, s, m, theta);
            Utils.FromLongArrayToByteArray(v, vTmp);


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
            long[] x = new long[N_BYTE_64];
            long[] y = new long[N_BYTE_64];
            byte[] pk = new byte[40 + N_BYTE];
            byte[] sigma = new byte[K_BYTE];
            ExtractKeysFromSecretKeys(y, sigma, pk, sk);

            // Extract u, v, d from ciphertext
            byte[] u = new byte[N_BYTE];
            byte[] v = new byte[N1N2_BYTE];
            byte[] salt = new byte[SALT_SIZE_BYTES];
            ExtractCiphertexts(u, v, salt, ct);

            // 1. Decrypt -> m'
            byte[] mPrimeBytes = new byte[k];
            int result = Decrypt(mPrimeBytes, mPrimeBytes, sigma, u, v, y);

            // 2. Compute theta'
            byte[] theta = new byte[64];
            byte[] tmp = new byte[K_BYTE + (SALT_SIZE_BYTES * 2) + SALT_SIZE_BYTES];
            Array.Copy(mPrimeBytes, 0, tmp, 0, mPrimeBytes.Length);
            Array.Copy(pk, 0, tmp, K_BYTE, SALT_SIZE_BYTES * 2);
            Array.Copy(salt, 0, tmp, K_BYTE + (SALT_SIZE_BYTES * 2), SALT_SIZE_BYTES);
            HqcKeccakRandomGenerator shakeDigest = new HqcKeccakRandomGenerator(256);
            shakeDigest.SHAKE256_512_ds(theta, tmp, tmp.Length, new[] { G_FCT_DOMAIN });

            // 3. Compute c' = Enc(pk, m', theta')
            // Extract public keys
            long[] h = new long[N_BYTE_64];
            byte[] s = new byte[N_BYTE];
            ExtractPublicKeys(h, s, pk);

            byte[] u2Bytes = new byte[N_BYTE];
            byte[] v2Bytes = new byte[N1N2_BYTE];
            long[] vTmp = new long[N1N2_BYTE_64];
            Encrypt(u2Bytes, vTmp, h, s, mPrimeBytes, theta);
            Utils.FromLongArrayToByteArray(v2Bytes, vTmp);


            // 5. Compute session key KPrime
            byte[] hashInputK = new byte[K_BYTE + N_BYTE + N1N2_BYTE];

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
                hashInputK[i] = (byte)(((mPrimeBytes[i] & result) ^ (sigma[i] & ~result)) & 0xff);
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
        private void Encrypt(byte[] u, long[] v, long[] h, byte[] s, byte[] m, byte[] theta)
        {
            // Randomly generate e, r1, r2
            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.SeedExpanderInit(theta, SEED_SIZE);
            long[] e = new long[N_BYTE_64];
            long[] r1 = new long[N_BYTE_64];
            long[] r2 = new long[N_BYTE_64];
            GenerateRandomFixedWeight(r2, randomGenerator, wr);
            GenerateRandomFixedWeight(e, randomGenerator, we);
            GenerateRandomFixedWeight(r1, randomGenerator, wr);

            // Calculate u
            long[] uLong = new long[N_BYTE_64];
            gfCalculator.MultLongs(uLong, r2, h);
            GF2PolynomialCalculator.AddLongs(uLong, uLong, r1);
            Utils.FromLongArrayToByteArray(u, uLong);

            // Calculate v
            // encode m
            byte[] res = new byte[n1];
            long[] vLong = new long[N1N2_BYTE_64];
            long[] tmpVLong = new long[N_BYTE_64];
            ReedSolomon.Encode(res, m, K_BYTE * 8, n1, k, g, generatorPoly);
            ReedMuller.Encode(vLong, res, n1, mulParam);
            Array.Copy(vLong, 0, tmpVLong, 0, vLong.Length);

            //Compute v
            long[] sLong = new long[N_BYTE_64];
            Utils.FromByteArrayToLongArray(sLong, s);

            long[] tmpLong = new long[N_BYTE_64];
            gfCalculator.MultLongs(tmpLong, r2, sLong);
            GF2PolynomialCalculator.AddLongs(tmpLong, tmpLong, tmpVLong);
            GF2PolynomialCalculator.AddLongs(tmpLong, tmpLong, e);

            Utils.ResizeArray(v, n1n2, tmpLong, n, N1N2_BYTE_64, N1N2_BYTE_64);
        }

        private int Decrypt(byte[] output, byte[] m, byte[] sigma, byte[] u, byte[] v, long[] y)
        {
            long[] uLongs = new long[N_BYTE_64];
            Utils.FromByteArrayToLongArray(uLongs, u);

            long[] vLongs = new long[N1N2_BYTE_64];
            Utils.FromByteArrayToLongArray(vLongs, v);

            long[] tmpV = new long[N_BYTE_64];
            Array.Copy(vLongs, 0, tmpV, 0, vLongs.Length);

            long[] tmpLong = new long[N_BYTE_64];
            gfCalculator.MultLongs(tmpLong, y, uLongs);
            GF2PolynomialCalculator.AddLongs(tmpLong, tmpLong, tmpV);

            // Decode res
            byte[] tmp = new byte[n1];
            ReedMuller.Decode(tmp, tmpLong, n1, mulParam);
            ReedSolomon.Decode(m, tmp, n1, fft, delta, k, g);

            Array.Copy(m, 0, output, 0, output.Length);
            return 0;
        }

        private void GenerateRandomFixedWeight(long[] output, HqcKeccakRandomGenerator random, int weight)
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
                support[i] = (int)(i + ((rand_u32[i]&0xFFFFFFFFL) % (n - i)));
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
                long val = output[i];
                for (int j = 0; j < weight; j++)
                {
                    long tmp = i ^ index_tab[j];
                    long mask = (tmp | -tmp) >> 63;
                    val |= bit_tab[j] & ~mask;
                }
                output[i] = val;
            }
        }

        void GeneratePublicKeyH(long[] output, HqcKeccakRandomGenerator random)
        {
            byte[] randBytes = new byte[N_BYTE];
            random.ExpandSeed(randBytes, N_BYTE);

            Utils.FromByteArrayToLongArray(output, randBytes);
            output[N_BYTE_64 - 1] &= (1L << (n & 63)) - 1L;
        }

        private void ExtractPublicKeys(long[] h, byte[] s, byte[] pk)
        {
            byte[] publicKeySeed = new byte[SEED_SIZE];
            Array.Copy(pk, 0, publicKeySeed, 0, publicKeySeed.Length);

            HqcKeccakRandomGenerator randomPublic = new HqcKeccakRandomGenerator(256);
            randomPublic.SeedExpanderInit(publicKeySeed, publicKeySeed.Length);

            GeneratePublicKeyH(h, randomPublic);

            Array.Copy(pk, 40, s, 0, s.Length);
        }

        private void ExtractKeysFromSecretKeys(long[] y, byte[] sigma, byte[] pk, byte[] sk)
        {
            byte[] secretKeySeed = new byte[SEED_SIZE];
            Array.Copy(sk, 0, secretKeySeed, 0, secretKeySeed.Length);
            Array.Copy(sk, SEED_SIZE, sigma, 0, K_BYTE);

            // Randomly generate secret keys x, y
            HqcKeccakRandomGenerator secretKeySeedExpander = new HqcKeccakRandomGenerator(256);
            secretKeySeedExpander.SeedExpanderInit(secretKeySeed, secretKeySeed.Length);
            
            GenerateRandomFixedWeight(y, secretKeySeedExpander, w);

            Array.Copy(sk, SEED_SIZE + K_BYTE, pk, 0, pk.Length);
        }

        private static void ExtractCiphertexts(byte[] u, byte[] v, byte[] salt, byte[] ct)
        {
            Array.Copy(ct, 0, u, 0, u.Length);
            Array.Copy(ct, u.Length, v, 0, v.Length);
            Array.Copy(ct, u.Length + v.Length, salt, 0, salt.Length);
        }
    }
}
