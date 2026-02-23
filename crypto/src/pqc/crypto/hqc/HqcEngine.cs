using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class HqcEngine
    {
        internal const int SharedSecretBytes = 32;
        private const int SaltBytes = 16;
        private const int SeedBytes = 32;

        private readonly int m_n;
        private readonly int m_n1;
        private readonly int m_k;
        private readonly int m_delta;
        private readonly int m_w;
        private readonly int m_wr;
        private readonly int m_g;
        private readonly int m_fft;
        private readonly int m_mulParam;
        private readonly int N_BYTE;
        private readonly int N1N2_BYTE_64;
        private readonly int N1N2_BYTE;
        private readonly int[] m_generatorPoly;
        private readonly int m_nMu;
        private readonly int m_pkSize;
        private readonly GF2x m_gf2x;
        private readonly int m_rejectionThreshold;
        private readonly int m_cipherTextBytes;

        internal HqcEngine(int n, int n1, int n2, int k, int g, int delta, int w, int wr, int fft, int nMu, int pkSize,
            int[] generatorPoly)
        {
            m_n = n;
            m_k = k;
            m_delta = delta;
            m_w = w;
            m_wr = wr;
            m_n1 = n1;
            m_generatorPoly = generatorPoly;
            m_g = g;
            m_fft = fft;
            m_nMu = nMu;
            m_pkSize = pkSize;
            m_mulParam = n2 >> 7;
            this.N_BYTE = Utils.GetByteSizeFromBitSize(n);
            this.N1N2_BYTE_64 = Utils.GetByte64SizeFromBitSize(n1 * n2);
            this.N1N2_BYTE = Utils.GetByteSizeFromBitSize(n1 * n2);
            m_gf2x = new GF2x(n);
            m_rejectionThreshold = ((1 << 24) / n) * n;
            m_cipherTextBytes = N_BYTE + N1N2_BYTE + 16;
        }

        internal int CipherTextBytes => m_cipherTextBytes;

        /**
         * Generate key pairs - Secret key : (x,y) - Public key: (h,s)
         *
         * @param pk output pk = (publicSeed||s)
         **/
        internal void GenKeyPair(byte[] pk, byte[] sk, SecureRandom secureRandom)
        {
            // Randomly generate seeds for secret keys and public keys
            byte[] seedKem = new byte[SeedBytes];
            byte[] keyPairSeed = new byte[SeedBytes << 1];
            ulong[] xLongBytes = m_gf2x.Create();
            ulong[] yLongBytes = m_gf2x.Create();
            ulong[] h = m_gf2x.Create(); // s

            secureRandom.NextBytes(seedKem);
            Shake256RandomGenerator ctxKem = new Shake256RandomGenerator(seedKem, 0x01);
            Array.Copy(seedKem, 0, sk, m_pkSize + SeedBytes + m_k, SeedBytes);

            ctxKem.NextBytes(seedKem);
            ctxKem.NextBytes(sk, m_pkSize + SeedBytes, m_k);

            HashHI(keyPairSeed, 512, seedKem, seedKem.Length, 0x02);
            ctxKem.Init(keyPairSeed, 0, SeedBytes, 0x01);

            VectSampleFixedWeight1(yLongBytes, ctxKem, m_w);
            VectSampleFixedWeight1(xLongBytes, ctxKem, m_w);
            Array.Copy(keyPairSeed, SeedBytes, pk, 0, SeedBytes);
            ctxKem.Init(keyPairSeed, SeedBytes, SeedBytes, 0x01);
            m_gf2x.Random(ctxKem, h);
            m_gf2x.Mul(h, yLongBytes, h); // h is s as the output
            m_gf2x.AddTo(xLongBytes, h); // h is s
            Utils.FromUInt64ArrayToByteArray(pk, SeedBytes, pk.Length - SeedBytes, h);
            Array.Copy(keyPairSeed, 0, sk, m_pkSize, SeedBytes);
            Array.Copy(pk, 0, sk, 0, m_pkSize);
            Arrays.Clear(keyPairSeed);
            m_gf2x.Clear(xLongBytes);
            m_gf2x.Clear(yLongBytes);
            m_gf2x.Clear(h);
        }

        /**
         * HQC Encapsulation - Input: pk, seed - Output: c = (u,v,d), K
         *
         * @param u u
         * @param v v
         * @param kTheta session key
         * @param pk public key
         **/
        internal void Encaps(byte[] u, byte[] v, byte[] kTheta, byte[] pk, byte[] salt, SecureRandom secureRandom)
        {
            // 1. Randomly generate m
            byte[] m = new byte[m_k];
            byte[] hashEkKem = new byte[SeedBytes];
            ulong[] u64 = m_gf2x.Create();
            ulong[] v64 = new ulong[N1N2_BYTE_64];

            secureRandom.NextBytes(m);
            secureRandom.NextBytes(salt);

            HashHI(hashEkKem, 256, pk, pk.Length, 0x01);
            HashGJ(kTheta, 512, hashEkKem, m, 0, m.Length, salt, 0, SaltBytes, 0x00);
            PkeEncrypt(u64, v64, pk, m, kTheta, SeedBytes);
            Utils.FromUInt64ArrayToByteArray(u, 0, u.Length, u64);
            Utils.FromUInt64ArrayToByteArray(v, 0, v.Length, v64);
            m_gf2x.Clear(u64);
            Arrays.Fill(v64, 0UL);
            Arrays.Clear(m);
            Arrays.Clear(hashEkKem);
        }

        /**
         * HQC Decapsulation - Input: ct, sk - Output: ss
         *
         * @param ss session key
         * @param ct ciphertext
         * @param sk secret key
         * @return 0 if decapsulation is successful, -1 otherwise
         **/
        internal int Decaps(byte[] ss, byte[] ct, byte[] sk)
        {
            // Extract Y and Public Keys from sk
            ulong[] u64 = m_gf2x.Create();
            ulong[] v64 = m_gf2x.Create();
            ulong[] cKemPrimeU64 = m_gf2x.Create(); // tmpLong
            ulong[] cKemPrimeV64 = m_gf2x.Create(); // y
            byte[] hashEkKem = new byte[SeedBytes];
            byte[] kThetaPrime = new byte[32 + SeedBytes];
            byte[] mPrime = new byte[m_k];
            byte[] kBar = new byte[32];
            byte[] tmp = new byte[m_n1];

            Shake256RandomGenerator generator = new Shake256RandomGenerator(sk, m_pkSize, SeedBytes, 0x01);
            VectSampleFixedWeight1(cKemPrimeV64, generator, m_w); // cKemPrimeV64 is y

            // Extract u, v, d from ciphertext
            Utils.FromByteArrayToUInt64Array(u64, ct, 0, N_BYTE);
            Utils.FromByteArrayToUInt64Array(v64, ct, N_BYTE, N1N2_BYTE);

            // cKemPrimeU64 is tmpLong
            m_gf2x.Mul(cKemPrimeV64, u64, cKemPrimeU64);
            VectTruncate(cKemPrimeU64);
            m_gf2x.AddTo(v64, cKemPrimeU64);

            ReedMuller.Decode(tmp, cKemPrimeU64, m_n1, m_mulParam);
            ReedSolomon.Decode(mPrime, tmp, m_n1, m_fft, m_delta, m_k, m_g);

            // Compute shared key K_prime and ciphertext cKemPrime
            HashHI(hashEkKem, 256, sk, m_pkSize, 0x01);
            HashGJ(kThetaPrime, 512, hashEkKem, mPrime, 0, mPrime.Length, ct, N_BYTE + N1N2_BYTE, SaltBytes, 0x00);
            Array.Copy(kThetaPrime, 0, ss, 0, 32);
            m_gf2x.Clear(cKemPrimeV64);
            PkeEncrypt(cKemPrimeU64, cKemPrimeV64, sk, mPrime, kThetaPrime, 32);
            HashGJ(kBar, 256, hashEkKem, sk, m_pkSize + SeedBytes, m_k, ct, 0, ct.Length, 0x03);

            int result = (int)(m_gf2x.EqualTo(u64, cKemPrimeU64) & m_gf2x.EqualTo(v64, cKemPrimeV64));

            for (int i = 0; i < m_k; i++)
            {
                ss[i] = (byte)((ss[i] & result) ^ (kBar[i] & ~result));
            }

            m_gf2x.Clear(u64);
            m_gf2x.Clear(v64);
            m_gf2x.Clear(cKemPrimeU64);
            m_gf2x.Clear(cKemPrimeV64);
            Arrays.Clear(hashEkKem);
            Arrays.Clear(kThetaPrime);
            Arrays.Clear(mPrime);
            Arrays.Clear(kBar);
            Arrays.Clear(tmp);
            return -result;
        }

        private void PkeEncrypt(ulong[] u, ulong[] v, byte[] ekPke, byte[] m, byte[] theta, int thetaOff)
        {
            ulong[] e = m_gf2x.Create(); // r2
            ulong[] tmp = m_gf2x.Create(); // s, h1, h
            byte[] res = new byte[m_n1];

            ReedSolomon.Encode(res, m, m_n1, m_k, m_g, m_generatorPoly);
            ReedMuller.Encode(v, res, m_n1, m_mulParam);

            var randomGenerator = new Shake256RandomGenerator(ekPke, 0, SeedBytes, 0x01);
            m_gf2x.Random(randomGenerator, tmp);

            randomGenerator.Init(theta, thetaOff, SeedBytes, 0x01);
            VectSampleFixedWeights2(randomGenerator, e, m_wr); // e is r2
            m_gf2x.Mul(tmp, e, u); // e is r2
            Utils.FromByteArrayToUInt64Array(tmp, ekPke, SeedBytes, m_pkSize - SeedBytes);
            m_gf2x.Mul(tmp, e, tmp);
            VectSampleFixedWeights2(randomGenerator, e, m_wr);
            m_gf2x.AddTo(e, tmp);
            VectTruncate(tmp);
            Nat.XorTo64(N1N2_BYTE_64, tmp, v);

            VectSampleFixedWeights2(randomGenerator, tmp, m_wr);// tmp is r1
            m_gf2x.AddTo(tmp, u);
            m_gf2x.Clear(e);
            m_gf2x.Clear(tmp);
            Arrays.Clear(res);
        }

        private int BarrettReduce(int x)
        {
            int q = (int)((ulong)((long)x * m_nMu) >> 32);
            int r = x - m_n - q * m_n;
            return r + ((r >> 31) & m_n);
        }

        private void GenerateRandomSupport(uint[] support, int weight, Shake256RandomGenerator random)
        {
            int randomBytesSize = 3 * weight;
            byte[] randBytes = new byte[randomBytesSize];
            int j = randomBytesSize;

            int count = 0;
            while (count < weight)
            {
                if (j == randomBytesSize)
                {
                    random.XofGetBytes(randBytes, randomBytesSize);
                    j = 0;
                }

                int candidate = ((int)randBytes[j++] << 16) | ((int)randBytes[j++] << 8) | (int)randBytes[j++];
                if (candidate >= m_rejectionThreshold)
                    continue;

                candidate = BarrettReduce(candidate);
                if (Array.IndexOf(support, (uint)candidate, 0, count) >= 0)
                    continue;

                support[count++] = (uint)candidate;
            }
        }

        private void WriteSupportToVector(ulong[] v, uint[] support, int weight)
        {
            int[] indexTab = new int[m_wr];
            long[] bitTab = new long[m_wr];
            for (int i = 0; i < weight; i++)
            {
                indexTab[i] = (int)(support[i] >> 6);
                bitTab[i] = 1L << ((int)support[i] & 0x3F);
            }
            for (int i = 0; i < v.Length; i++)
            {
                long val = 0;
                for (int j = 0; j < weight; j++)
                {
                    int tmp = i - indexTab[j];
                    val |= bitTab[j] & ~((tmp | -tmp) >> 31);
                }
                v[i] = (ulong)val;
            }
        }

        private void VectSampleFixedWeight1(ulong[] output, Shake256RandomGenerator random, int weight)
        {
            uint[] support = new uint[m_wr];
            GenerateRandomSupport(support, weight, random);
            WriteSupportToVector(output, support, weight);
        }

        private void VectSampleFixedWeights2(Shake256RandomGenerator generator, ulong[] v, int weight)
        {
            byte[] rand = new byte[m_wr << 2];
            generator.XofGetBytes(rand, rand.Length);

            uint[] support = new uint[m_wr];
            Pack.LE_To_UInt32(rand, 0, support);

            int i = weight;
            while (--i >= 0)
            {
                int support_i = i + (int)(((long)support[i] * (m_n - i)) >> 32);
                int notFound = -1;
                for (int j = i + 1; j < weight; ++j)
                {
                    notFound &= CDiff(support_i, (int)support[j]);
                }
                support[i] = (uint)((~notFound & i) ^ (notFound & support_i));
            }

            WriteSupportToVector(v, support, weight);
        }

        private void VectTruncate(ulong[] v) => Arrays.Fill(v, N1N2_BYTE_64, (m_n + 63) >> 6, 0UL);

        private static int CDiff(int v1, int v2) => ((v1 - v2) | (v2 - v1)) >> 31;

        private static void HashGJ(byte[] output, int bitLength, byte[] hashEkKem, byte[] mOrSigma, int mOrSigmaOff,
            int mOrSigmaLen, byte[] saltOrCt, int saltOrCtOff, int saltOrCtOffLen, byte domain)
        {
            Sha3Digest digest = new Sha3Digest(bitLength);
            digest.BlockUpdate(hashEkKem, 0, hashEkKem.Length);
            digest.BlockUpdate(mOrSigma, mOrSigmaOff, mOrSigmaLen);
            digest.BlockUpdate(saltOrCt, saltOrCtOff, saltOrCtOffLen);
            digest.Update(domain);
            digest.DoFinal(output, 0);
        }

        private static void HashHI(byte[] output, int bitLength, byte[] input, int inLen, byte domain)
        {
            Sha3Digest digest = new Sha3Digest(bitLength);
            digest.BlockUpdate(input, 0, inLen);
            digest.Update(domain);
            digest.DoFinal(output, 0);
        }
    }
}
