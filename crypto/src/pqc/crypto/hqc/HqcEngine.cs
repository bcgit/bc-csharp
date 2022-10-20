using System;

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
        private byte H_FCT_DOMAIN = 4;
        private byte K_FCT_DOMAIN = 5;

        private int N_BYTE;
        private int n1n2;
        private int N_BYTE_64;
        private int K_BYTE;
        private int K_BYTE_64;
        private int N1_BYTE_64;
        private int N1N2_BYTE_64;
        private int N1N2_BYTE;
        private int N1_BYTE;

        private int[] generatorPoly;
        private int SHA512_BYTES = 512 / 8;

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
            this.n1n2 = n1 * n2;
            this.generatorPoly = generatorPoly;
            this.g = g;
            this.rejectionThreshold = rejectionThreshold;
            this.fft = fft;

            this.mulParam = (n2 + 127) / 128;
            this.N_BYTE = Utils.GetByteSizeFromBitSize(n);
            this.K_BYTE = k;
            this.N_BYTE_64 = Utils.GetByte64SizeFromBitSize(n);
            this.K_BYTE_64 = Utils.GetByteSizeFromBitSize(k);
            this.N1_BYTE_64 = Utils.GetByteSizeFromBitSize(n1);
            this.N1N2_BYTE_64 = Utils.GetByte64SizeFromBitSize(n1 * n2);
            this.N1N2_BYTE = Utils.GetByteSizeFromBitSize(n1 * n2);
            this.N1_BYTE = Utils.GetByteSizeFromBitSize(n1);
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

            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.RandomGeneratorInit(seed, null, seed.Length, 0);
            randomGenerator.Squeeze(secretKeySeed, 40);

            // 1. Randomly generate secret keys x, y
            HqcKeccakRandomGenerator secretKeySeedExpander = new HqcKeccakRandomGenerator(256);
            secretKeySeedExpander.SeedExpanderInit(secretKeySeed, secretKeySeed.Length);

            ulong[] xLongBytes = new ulong[N_BYTE_64];
            int[] yPos = new int[this.w];

            GenerateSecretKey(xLongBytes, secretKeySeedExpander, w);
            GenerateSecretKeyByCoordinates(yPos, secretKeySeedExpander, w);

            // 2. Randomly generate h
            byte[] publicKeySeed = new byte[SEED_SIZE];
            randomGenerator.Squeeze(publicKeySeed, 40);

            HqcKeccakRandomGenerator randomPublic = new HqcKeccakRandomGenerator(256);
            randomPublic.SeedExpanderInit(publicKeySeed, publicKeySeed.Length);

            ulong[] hLongBytes = new ulong[N_BYTE_64];
            GeneratePublicKeyH(hLongBytes, randomPublic);

            // 3. Compute s
            ulong[] s = new ulong[N_BYTE_64];
            GF2PolynomialCalculator.ModMult(s, yPos, hLongBytes, w, n, N_BYTE_64, we, secretKeySeedExpander);
            GF2PolynomialCalculator.AddULongs(s, s, xLongBytes);
            byte[] sBytes = new byte[N_BYTE];
            Utils.FromULongArrayToByteArray(sBytes, s);

            byte[] tmpPk = Arrays.Concatenate(publicKeySeed, sBytes);
            byte[] tmpSk = Arrays.Concatenate(secretKeySeed, tmpPk);

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
        public void Encaps(byte[] u, byte[] v, byte[] K, byte[] d, byte[] pk, byte[] seed)
        {
            // 1. Randomly generate m
            byte[] m = new byte[K_BYTE];

            // TODO: no way to gen m without seed and gen skseed, pkseed. In reference implementation they use the same
            byte[] secretKeySeed = new byte[SEED_SIZE];
            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.RandomGeneratorInit(seed, null, seed.Length, 0);
            randomGenerator.Squeeze(secretKeySeed, 40);

            byte[] publicKeySeed = new byte[SEED_SIZE];
            randomGenerator.Squeeze(publicKeySeed, 40);

            // gen m
            randomGenerator.Squeeze(m, K_BYTE);

            // 2. Generate theta
            byte[] theta = new byte[SHA512_BYTES];
            HqcKeccakRandomGenerator shakeDigest = new HqcKeccakRandomGenerator(256);
            shakeDigest.SHAKE256_512_ds(theta, m, m.Length, new byte[] { G_FCT_DOMAIN });

            // 3. Generate ciphertext c = (u,v)
            // Extract public keys
            ulong[] h = new ulong[N_BYTE_64];
            byte[] s = new byte[N_BYTE];
            ExtractPublicKeys(h, s, pk);

            ulong[] vTmp = new ulong[N1N2_BYTE_64];
            Encrypt(u, vTmp, h, s, m, theta);
            Utils.FromULongArrayToByteArray(v, vTmp);

            // 4. Compute d
            shakeDigest.SHAKE256_512_ds(d, m, m.Length, new byte[] { H_FCT_DOMAIN });

            // 5. Compute session key K
            byte[] hashInputK = new byte[K_BYTE + N_BYTE + N1N2_BYTE];
            hashInputK = Arrays.Concatenate(m, u);
            hashInputK = Arrays.Concatenate(hashInputK, v);
            shakeDigest.SHAKE256_512_ds(K, hashInputK, hashInputK.Length, new byte[] { K_FCT_DOMAIN });
        }

        /**
         * HQC Decapsulation
         * - Input: ct, sk
         * - Output: ss
         *
         * @param ss session key
         * @param ct ciphertext
         * @param sk secret key
         **/
        public void Decaps(byte[] ss, byte[] ct, byte[] sk)
        {
            //Extract Y and Public Keys from sk
            int[] yPos = new int[this.w];
            byte[] pk = new byte[40 + N_BYTE];
            ExtractKeysFromSecretKeys(yPos, pk, sk);

            // Extract u, v, d from ciphertext
            byte[] u = new byte[N_BYTE];
            byte[] v = new byte[N1N2_BYTE];
            byte[] d = new byte[SHA512_BYTES];
            HqcEngine.ExtractCiphertexts(u, v, d, ct);

            // 1. Decrypt -> m'
            byte[] mPrimeBytes = new byte[k];
            Decrypt(mPrimeBytes, mPrimeBytes, u, v, yPos);

            // 2. Compute theta'
            byte[] theta = new byte[SHA512_BYTES];
            HqcKeccakRandomGenerator shakeDigest = new HqcKeccakRandomGenerator(256);
            shakeDigest.SHAKE256_512_ds(theta, mPrimeBytes, mPrimeBytes.Length, new byte[] { G_FCT_DOMAIN });

            // 3. Compute c' = Enc(pk, m', theta')
            // Extract public keys
            ulong[] h = new ulong[N_BYTE_64];
            byte[] s = new byte[N_BYTE];
            ExtractPublicKeys(h, s, pk);

            byte[] u2Bytes = new byte[N_BYTE];
            byte[] v2Bytes = new byte[N1N2_BYTE];
            ulong[] vTmp = new ulong[N1N2_BYTE_64];
            Encrypt(u2Bytes, vTmp, h, s, mPrimeBytes, theta);
            Utils.FromULongArrayToByteArray(v2Bytes, vTmp);

            // 4. Compute d' = H(m')
            byte[] dPrime = new byte[SHA512_BYTES];
            shakeDigest.SHAKE256_512_ds(dPrime, mPrimeBytes, mPrimeBytes.Length, new byte[] { H_FCT_DOMAIN });

            // 5. Compute session key KPrime
            byte[] hashInputK = new byte[K_BYTE + N_BYTE + N1N2_BYTE];
            hashInputK = Arrays.Concatenate(mPrimeBytes, u);
            hashInputK = Arrays.Concatenate(hashInputK, v);
            shakeDigest.SHAKE256_512_ds(ss, hashInputK, hashInputK.Length, new byte[] { K_FCT_DOMAIN });

            int result = 1;
            // Compare u, v, d
            if (!Arrays.AreEqual(u, u2Bytes))
            {
                result = 0;
            }

            if (!Arrays.AreEqual(v, v2Bytes))
            {
                result = 0;
            }

            if (!Arrays.AreEqual(d, dPrime))
            {
                result = 0;
            }

            if (result == 0)
            { //abort
                for (int i = 0; i < GetSessionKeySize(); i++)
                {
                    ss[i] = 0;
                }
            }
        }

        internal int GetSessionKeySize()
        {
            return SHA512_BYTES;
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
            randomGenerator.SeedExpanderInit(theta, SEED_SIZE);
            ulong[] e = new ulong[N_BYTE_64];
            ulong[] r1 = new ulong[N_BYTE_64];
            int[] r2 = new int[wr];
            GenerateSecretKey(r1, randomGenerator, wr);
            GenerateSecretKeyByCoordinates(r2, randomGenerator, wr);
            GenerateSecretKey(e, randomGenerator, we);

            // Calculate u
            ulong[] uLong = new ulong[N_BYTE_64];
            GF2PolynomialCalculator.ModMult(uLong, r2, h, wr, n, N_BYTE_64, we, randomGenerator);
            GF2PolynomialCalculator.AddULongs(uLong, uLong, r1);
            Utils.FromULongArrayToByteArray(u, uLong);

            // Calculate v
            // encode m
            byte[] res = new byte[n1];
            ulong[] vLong = new ulong[N1N2_BYTE_64];
            ulong[] tmpVLong = new ulong[N_BYTE_64];
            ReedSolomon.Encode(res, m, K_BYTE * 8, n1, k, g, generatorPoly);
            ReedMuller.Encode(vLong, res, n1, mulParam);
            Array.Copy(vLong, 0, tmpVLong, 0, vLong.Length);

            //Compute v
            ulong[] sLong = new ulong[N_BYTE_64];
            Utils.FromByteArrayToULongArray(sLong, s);

            ulong[] tmpLong = new ulong[N_BYTE_64];
            GF2PolynomialCalculator.ModMult(tmpLong, r2, sLong, wr, n, N_BYTE_64, we, randomGenerator);
            GF2PolynomialCalculator.AddULongs(tmpLong, tmpLong, tmpVLong);
            GF2PolynomialCalculator.AddULongs(tmpLong, tmpLong, e);

            Utils.ResizeArray(v, n1n2, tmpLong, n, N1N2_BYTE_64, N1N2_BYTE_64);
        }

        private void Decrypt(byte[] output, byte[] m, byte[] u, byte[] v, int[] y)
        {
            byte[] tmpSeed = new byte[SEED_SIZE];
            HqcKeccakRandomGenerator randomGenerator = new HqcKeccakRandomGenerator(256);
            randomGenerator.SeedExpanderInit(tmpSeed, SEED_SIZE);

            ulong[] uLongs = new ulong[N_BYTE_64];
            Utils.FromByteArrayToULongArray(uLongs, u);

            ulong[] vLongs = new ulong[N1N2_BYTE_64];
            Utils.FromByteArrayToULongArray(vLongs, v);

            ulong[] tmpV = new ulong[N_BYTE_64];
            Array.Copy(vLongs, 0, tmpV, 0, vLongs.Length);

            ulong[] tmpLong = new ulong[N_BYTE_64];
            GF2PolynomialCalculator.ModMult(tmpLong, y, uLongs, w, n, N_BYTE_64, we, randomGenerator);
            GF2PolynomialCalculator.AddULongs(tmpLong, tmpLong, tmpV);

            // Decode res
            byte[] tmp = new byte[n1];
            ReedMuller.Decode(tmp, tmpLong, n1, mulParam);
            ReedSolomon.Decode(m, tmp, n1, fft, delta, k, g);

            Array.Copy(m, 0, output, 0, output.Length);
        }

        private void GenerateSecretKey(ulong[] output, HqcKeccakRandomGenerator random, int w)
        {
            int[] tmp = new int[w];
            GenerateSecretKeyByCoordinates(tmp, random, w);

            for (int i = 0; i < w; ++i)
            {
                int index = tmp[i] / 64;
                int pos = tmp[i] % 64;
                ulong t = 1UL << pos;
                output[index] |= t;
            }
        }

        private void GenerateSecretKeyByCoordinates(int[] output, HqcKeccakRandomGenerator random, int w)
        {
            int randomByteSize = 3 * w;
            byte[] randomBytes = new byte[3 * this.wr];
            int inc;

            int i = 0;
            int j = randomByteSize;
            while (i < w)
            {
                do
                {
                    if (j == randomByteSize)
                    {
                        random.ExpandSeed(randomBytes, randomByteSize);

                        j = 0;
                    }

                    output[i] = (randomBytes[j++] & 0xff) << 16;
                    output[i] |= (randomBytes[j++] & 0xff) << 8;
                    output[i] |= (randomBytes[j++] & 0xff);

                }
                while (output[i] >= this.rejectionThreshold);

                output[i] = output[i] % this.n;
                inc = 1;
                for (int k = 0; k < i; k++)
                {
                    if (output[k] == output[i])
                    {
                        inc = 0;
                    }
                }
                i += inc;
            }
        }

        void GeneratePublicKeyH(ulong[] output, HqcKeccakRandomGenerator random)
        {
            byte[] randBytes = new byte[N_BYTE];
            random.ExpandSeed(randBytes, N_BYTE);
            ulong[] tmp = new ulong[N_BYTE_64];
            Utils.FromByteArrayToULongArray(tmp, randBytes);
            tmp[N_BYTE_64 - 1] &= Utils.BitMask((ulong)n, 64);
            Array.Copy(tmp, 0, output, 0, output.Length);
        }

        private void ExtractPublicKeys(ulong[] h, byte[] s, byte[] pk)
        {
            byte[] publicKeySeed = new byte[SEED_SIZE];
            Array.Copy(pk, 0, publicKeySeed, 0, publicKeySeed.Length);

            HqcKeccakRandomGenerator randomPublic = new HqcKeccakRandomGenerator(256);
            randomPublic.SeedExpanderInit(publicKeySeed, publicKeySeed.Length);

            ulong[] hLongBytes = new ulong[N_BYTE_64];
            GeneratePublicKeyH(hLongBytes, randomPublic);

            Array.Copy(hLongBytes, 0, h, 0, h.Length);
            Array.Copy(pk, 40, s, 0, s.Length);
        }

        private void ExtractKeysFromSecretKeys(int[] y, byte[] pk, byte[] sk)
        {
            byte[] secretKeySeed = new byte[SEED_SIZE];
            Array.Copy(sk, 0, secretKeySeed, 0, secretKeySeed.Length);

            // Randomly generate secret keys x, y
            HqcKeccakRandomGenerator secretKeySeedExpander = new HqcKeccakRandomGenerator(256);
            secretKeySeedExpander.SeedExpanderInit(secretKeySeed, secretKeySeed.Length);

            ulong[] xLongBytes = new ulong[N_BYTE_64];
            int[] yPos = new int[this.w];

            GenerateSecretKey(xLongBytes, secretKeySeedExpander, w);
            GenerateSecretKeyByCoordinates(yPos, secretKeySeedExpander, w);

            Array.Copy(yPos, 0, y, 0, yPos.Length);
            Array.Copy(sk, SEED_SIZE, pk, 0, pk.Length);
        }

        private static void ExtractCiphertexts(byte[] u, byte[] v, byte[] d, byte[] ct)
        {
            Array.Copy(ct, 0, u, 0, u.Length);
            Array.Copy(ct, u.Length, v, 0, v.Length);
            Array.Copy(ct, u.Length + v.Length, d, 0, d.Length);
        }
    }
}
