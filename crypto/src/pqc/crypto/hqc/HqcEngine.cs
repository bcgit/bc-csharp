using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /**
     * HQC-PKE and HQC-KEM of the HQC specification of 2026-10-12 (Sections 3.6 and 3.7).
     * <p>
     * The decapsulation key dkKEM is the 32-byte seedKEM alone. Everything decapsulation needs is re-derived from it -
     * ctxKEM = XOF.Init(seedKEM || k), seedPKE = GetBytes(32), sigma = GetBytes(k), (ekPKE, dkPKE) =
     * HQC-PKE.Keygen(seedPKE) - and that derivation costs a key generation, so <see cref="ExpandSecretKey"/> performs
     * it once into the "expanded key" ekPKE || seedPKE.dk || sigma, which <see cref="HqcPrivateKeyParameters"/> caches
     * and <see cref="Decaps"/> consumes.
     * </p>
     * <p>
     * NOTE: the specification text writes ctxKEM = XOF.Init(seedKEM), with nothing appended (Section 3.7, Keygen step 3
     * and Decaps step 2). The reference implementation absorbs seedKEM followed by k (in bytes: 16, 24 or 32) as a
     * single byte, so a seed reused across parameter sets yields unrelated keys, and the known-answer tests follow the
     * code. This implementation follows the reference implementation and its known-answer tests.
     * </p>
     */
    internal class HqcEngine
    {
        internal const int SharedSecretBytes = 32;
        internal const int SeedBytes = 32;
        private const int SaltBytes = 16;

        private readonly int m_n;
        private readonly int m_n1;
        private readonly int m_k;
        private readonly int m_delta;
        private readonly int m_w;
        private readonly int m_wr;
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

        internal HqcEngine(int n, int n1, int n2, int k, int delta, int w, int wr, int fft, int nMu, int pkSize,
            int[] generatorPoly)
        {
            m_n = n;
            m_k = k;
            m_delta = delta;
            m_w = w;
            m_wr = wr;
            m_n1 = n1;
            m_generatorPoly = generatorPoly;
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

        /** Size of the expanded decapsulation key ekPKE || seedPKE.dk || sigma. */
        internal int ExpandedKeyBytes => m_pkSize + SeedBytes + m_k;

        /**
         * HQC-KEM.Keygen: sample seedKEM, which is the decapsulation key, and expand it.
         *
         * @param pk      output ekKEM = ekPKE = (seedPKE.ek || s)
         * @param seedKem output dkKEM = seedKEM
         * @return the expanded key ekPKE || seedPKE.dk || sigma, for {@link #Decaps}
         **/
        internal byte[] GenKeyPair(byte[] pk, byte[] seedKem, SecureRandom secureRandom)
        {
            secureRandom.NextBytes(seedKem);

            byte[] expanded = ExpandSecretKey(seedKem);
            Array.Copy(expanded, 0, pk, 0, m_pkSize);
            return expanded;
        }

        /**
         * Derive from dkKEM = seedKEM everything HQC-KEM.Decaps needs: seedPKE and sigma from
         * ctxKEM = XOF.Init(seedKEM || k), then (ekPKE, dkPKE) = HQC-PKE.Keygen(seedPKE) with dkPKE = seedPKE.dk,
         * (seedPKE.dk, seedPKE.ek) = I(seedPKE), y then x sampled from XOF(seedPKE.dk) by SampleFixedWeightVect$,
         * h from XOF(seedPKE.ek) and s = x + h.y.
         *
         * @param seedKem the 32-byte seedKEM
         * @return ekPKE || seedPKE.dk || sigma
         **/
        internal byte[] ExpandSecretKey(byte[] seedKem)
        {
            byte[] expanded = new byte[ExpandedKeyBytes];
            byte[] seedPke = new byte[SeedBytes];
            byte[] keyPairSeed = new byte[SeedBytes << 1];
            ulong[] y = m_gf2x.Create();
            ulong[] h = m_gf2x.Create(); // becomes s

            // k is absorbed after seedKEM as the reference implementation does; see the class comment
            var ctxKem = new Shake256RandomGenerator(seedKem, 0, SeedBytes, (byte)m_k);
            ctxKem.NextBytes(seedPke);
            ctxKem.NextBytes(expanded, m_pkSize + SeedBytes, m_k); // sigma

            HashHI(keyPairSeed, 512, seedPke, SeedBytes, 0x02); // (seedPKE.dk, seedPKE.ek) = I(seedPKE)
            ctxKem.Init(keyPairSeed, 0, SeedBytes); // XOF(seedPKE.dk)

            uint[] ySupport = SampleSupport1(ctxKem, m_w);
            uint[] xSupport = SampleSupport1(ctxKem, m_w);
            WriteSupportToVector(y, ySupport, m_w);

            ctxKem.Init(keyPairSeed, SeedBytes, SeedBytes); // XOF(seedPKE.ek)
            m_gf2x.Random(ctxKem, h);
            m_gf2x.Mul(h, y, h); // s = h.y
            AddSupportTo(h, xSupport, m_w); // s ^= x

            Array.Copy(keyPairSeed, SeedBytes, expanded, 0, SeedBytes); // ekPKE = seedPKE.ek || s
            Utils.FromUInt64ArrayToByteArray(expanded, SeedBytes, m_pkSize - SeedBytes, h);
            Array.Copy(keyPairSeed, 0, expanded, m_pkSize, SeedBytes); // dkPKE = seedPKE.dk

            Arrays.ZeroMemory(seedPke);
            Arrays.ZeroMemory(keyPairSeed);
            Arrays.ZeroMemory(ySupport);
            Arrays.ZeroMemory(xSupport);
            m_gf2x.Clear(y);
            m_gf2x.Clear(h);
            return expanded;
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
            Nat.Zero64(v64.Length, v64);
            Arrays.ZeroMemory(m);
            Arrays.Clear(hashEkKem);
        }

        /**
         * HQC Decapsulation - Input: ct, expanded sk - Output: ss
         *
         * @param ss session key
         * @param ct ciphertext
         * @param sk the expanded decapsulation key ekPKE || seedPKE.dk || sigma from {@link #ExpandSecretKey}
         * @return 0 if decapsulation is successful, -1 otherwise
         **/
        internal int Decaps(byte[] ss, byte[] ct, byte[] sk)
        {
            // Recompute y from seedPKE.dk; ekPKE and sigma are read from sk in place
            ulong[] u64 = m_gf2x.Create();
            ulong[] v64 = new ulong[N1N2_BYTE_64]; // ciphertext v: an n1*n2-bit codeword, not a ring element
            ulong[] cKemPrimeU64 = m_gf2x.Create(); // tmpLong
            ulong[] cKemPrimeV64 = m_gf2x.Create(); // re-encryption v scratch
            byte[] hashEkKem = new byte[SeedBytes];
            byte[] kThetaPrime = new byte[32 + SeedBytes];
            byte[] mPrime = new byte[m_k];
            byte[] kBar = new byte[32];
            byte[] tmp = new byte[m_n1];

            Shake256RandomGenerator generator = new Shake256RandomGenerator(sk, m_pkSize, SeedBytes);
            uint[] ySupport = SampleSupport1(generator, m_w);
            WriteSupportToVector(cKemPrimeV64, ySupport, m_w); // cKemPrimeV64 holds dense y for the multiply

            // Extract u, v, d from ciphertext
            Utils.FromByteArrayToUInt64Array(u64, ct, 0, N_BYTE);
            Utils.FromByteArrayToUInt64Array(v64, ct, N_BYTE, N1N2_BYTE);

            // cKemPrimeU64 is tmpLong
            m_gf2x.Mul(cKemPrimeV64, u64, cKemPrimeU64);
            VectTruncate(cKemPrimeU64);
            Nat.XorTo64(N1N2_BYTE_64, v64, cKemPrimeU64); // cKemPrimeU64 ^= v over the codeword limbs

            ReedMuller.Decode(tmp, cKemPrimeU64, m_n1, m_mulParam);
            ReedSolomon.Decode(mPrime, tmp, m_n1, m_fft, m_delta, m_k, m_generatorPoly.Length);

            // Compute shared key K_prime and ciphertext cKemPrime
            HashHI(hashEkKem, 256, sk, m_pkSize, 0x01);
            HashGJ(kThetaPrime, 512, hashEkKem, mPrime, 0, mPrime.Length, ct, N_BYTE + N1N2_BYTE, SaltBytes, 0x00);
            Array.Copy(kThetaPrime, 0, ss, 0, 32);
            m_gf2x.Clear(cKemPrimeV64); // clear y before reusing cKemPrimeV64 for the re-encryption v
            PkeEncrypt(cKemPrimeU64, cKemPrimeV64, sk, mPrime, kThetaPrime, 32);
            HashGJ(kBar, 256, hashEkKem, sk, m_pkSize + SeedBytes, m_k, ct, 0, ct.Length, 0x03);

            // u is a full ring element; v is an n1*n2-bit codeword, so compare it over just the codeword
            // limbs (cKemPrimeV64's higher limbs are unused re-encryption scratch).
            int result = (int)(m_gf2x.EqualTo(u64, cKemPrimeU64) & Nat.EqualTo64(N1N2_BYTE_64, v64, cKemPrimeV64));

            // On re-encryption failure the implicit-rejection secret kBar must replace the *entire*
            // shared secret. Bounding this by m_k would leave ss[m_k..] holding K' = G(H(pk)||m'||salt),
            // which depends on the decrypted m' - an FO/IND-CCA break for the parameter sets with
            // m_k < SharedSecretBytes (HQC-128: 16, HQC-192: 24).
            for (int i = 0; i < SharedSecretBytes; i++)
            {
                ss[i] = (byte)((ss[i] & result) ^ (kBar[i] & ~result));
            }

            m_gf2x.Clear(u64);
            Nat.Zero64(v64.Length, v64);
            m_gf2x.Clear(cKemPrimeU64);
            m_gf2x.Clear(cKemPrimeV64);
            Arrays.ZeroMemory(ySupport);
            Arrays.Clear(hashEkKem);
            Arrays.ZeroMemory(kThetaPrime);
            Arrays.ZeroMemory(mPrime);
            Arrays.ZeroMemory(kBar);
            Arrays.ZeroMemory(tmp);
            return -result;
        }

        private void PkeEncrypt(ulong[] u, ulong[] v, byte[] ekPke, byte[] m, byte[] theta, int thetaOff)
        {
            ulong[] r2Dense = m_gf2x.Create();
            ulong[] tmp = m_gf2x.Create(); // s, h1, h
            byte[] res = new byte[m_n1];

            ReedSolomon.Encode(res, m, m_n1, m_k, m_generatorPoly);
            ReedMuller.Encode(v, res, m_n1, m_mulParam);

            var randomGenerator = new Shake256RandomGenerator(ekPke, 0, SeedBytes);
            m_gf2x.Random(randomGenerator, tmp);

            randomGenerator.Init(theta, thetaOff, SeedBytes);
            uint[] r2Support = SampleSupport2(randomGenerator, m_wr);
            WriteSupportToVector(r2Dense, r2Support, m_wr);
            m_gf2x.Mul(tmp, r2Dense, u);
            Utils.FromByteArrayToUInt64Array(tmp, ekPke, SeedBytes, m_pkSize - SeedBytes);
            m_gf2x.Mul(tmp, r2Dense, tmp);
            uint[] eSupport = SampleSupport2(randomGenerator, m_wr);
            AddSupportTo(tmp, eSupport, m_wr); // tmp ^= e
            VectTruncate(tmp);
            Nat.XorTo64(N1N2_BYTE_64, tmp, v);

            uint[] r1Support = SampleSupport2(randomGenerator, m_wr);
            AddSupportTo(u, r1Support, m_wr); // u ^= r1
            Arrays.ZeroMemory(r2Support);
            Arrays.ZeroMemory(eSupport);
            Arrays.ZeroMemory(r1Support);
            m_gf2x.Clear(r2Dense);
            m_gf2x.Clear(tmp);
            Arrays.ZeroMemory(res);
        }

        private int BarrettReduce(int x)
        {
            int q = (int)((ulong)((long)x * m_nMu) >> 32);
            int r = x - m_n - q * m_n;
            return r + ((r >> 31) & m_n);
        }

        /**
         * SampleSupport1: rejection-sample <paramref name="weight"/> distinct positions in [0, n) into
         * <paramref name="support"/>, squeezing one 3-byte little-endian candidate at a time from the XOF and keeping
         * it when it lies below rejection_threshold_n (so that reduction modulo n is unbiased) and is not already in
         * the support.
         * <p>
         * NOTE: this runs on secret data at both of its call sites - it samples the secret key supports y and x in
         * {@link #ExpandSecretKey}, which also happens on every decapsulation of a key whose expansion is not cached,
         * where the same seed produces the same draw sequence every time and so any timing variation is a fixed,
         * repeatedly measurable function of the private key. The work done on each candidate is therefore branch-free
         * and fixed-count: the duplicate scan visits every slot with no early exit, and an accepted candidate is
         * written by masking across all slots rather than by indexing with the secret running count. Do not
         * "optimise" any of that back into a break, a continue, or a {@code support[count]} store.
         * </p>
         * <p>
         * The number of candidates drawn before <paramref name="weight"/> are accepted is data-dependent, which is
         * inherent to the specified sampler (the reference implementation's loop is the same shape) and cannot be
         * removed without changing the bytes consumed from the XOF, and therefore the key.
         * </p>
         */
        private void GenerateRandomSupport(uint[] support, int weight, Shake256RandomGenerator random)
        {
            byte[] randBytes = new byte[3];

            int count = 0;
            while (count < weight)
            {
                random.NextBytes(randBytes);

                int candidate = randBytes[0] | (randBytes[1] << 8) | (randBytes[2] << 16);

                // in range for an unbiased reduction
                int accept = (candidate - m_rejectionThreshold) >> 31;
                int reduced = BarrettReduce(candidate);

                // drop a repeat: every slot is compared, the not-yet-filled ones counting as non-matching, so
                // neither the trip count nor the exit depends on the values
                for (int t = 0; t < weight; ++t)
                {
                    int live = (t - count) >> 31;
                    accept &= CDiff(reduced, (int)support[t]) | ~live;
                }

                // store at index count without using count as an index
                for (int t = 0; t < weight; ++t)
                {
                    int hit = accept & ~CDiff(t, count);
                    support[t] = (support[t] & ~(uint)hit) | ((uint)reduced & (uint)hit);
                }

                count -= accept; // accept is 0 or -1
            }

            Arrays.ZeroMemory(randBytes);
        }

        /**
         * Constant-time materialisation of a fixed-weight sparse vector (given as its support
         * indices) into a dense ulong[] target, every word of which is overwritten. Branchless mask-OR
         * over every (i, j) pair, so neither timing nor cache-access patterns leak the secret support.
         */
        private void WriteSupportToVector(ulong[] v, uint[] support, int weight)
        {
            int[] indexTab = new int[m_wr];
            ulong[] bitTab = new ulong[m_wr];
            for (int i = 0; i < weight; i++)
            {
                indexTab[i] = (int)(support[i] >> 6);
                bitTab[i] = 1UL << ((int)support[i] & 0x3F);
            }
            for (int i = 0; i < v.Length; i++)
            {
                ulong val = 0;
                for (int j = 0; j < weight; j++)
                {
                    int tmp = i - indexTab[j];
                    long mask = ~((tmp | -tmp) >> 31);
                    val |= bitTab[j] & (ulong)mask;
                }
                v[i] = val;
            }

            // indexTab and bitTab are the secret support positions
            Arrays.ZeroMemory(indexTab, 0, indexTab.Length);
            Arrays.ZeroMemory(bitTab);
        }

        /**
         * Constant-time XOR of a fixed-weight sparse vector (given as its support indices) into a
         * dense ulong[] target. Equivalent to materialising the sparse vector to a dense ulong[] and
         * then XORing it into <paramref name="v"/>, but in a single pass without the dense intermediate.
         * The (i, j) iteration pattern matches <see cref="WriteSupportToVector"/>'s constant-time
         * branchless mask-OR, so timing and cache-access do not leak the secret support indices.
         */
        private void AddSupportTo(ulong[] v, uint[] support, int weight)
        {
            int[] indexTab = new int[m_wr];
            ulong[] bitTab = new ulong[m_wr];
            for (int i = 0; i < weight; i++)
            {
                indexTab[i] = (int)(support[i] >> 6);
                bitTab[i] = 1UL << ((int)support[i] & 0x3F);
            }
            for (int i = 0; i < v.Length; i++)
            {
                ulong val = v[i];
                for (int j = 0; j < weight; j++)
                {
                    int tmp = i - indexTab[j];
                    long mask = ~((tmp | -tmp) >> 31);
                    val ^= bitTab[j] & (ulong)mask;
                }
                v[i] = val;
            }

            // indexTab and bitTab are the secret support positions
            Arrays.ZeroMemory(indexTab, 0, indexTab.Length);
            Arrays.ZeroMemory(bitTab);
        }

        private uint[] SampleSupport1(Shake256RandomGenerator random, int weight)
        {
            uint[] support = new uint[m_wr];
            GenerateRandomSupport(support, weight, random);
            return support;
        }

        private uint[] SampleSupport2(Shake256RandomGenerator generator, int weight)
        {
            byte[] rand = new byte[m_wr << 2];
            generator.XofGetBytes(rand, rand.Length);

            uint[] support = new uint[m_wr];
            Pack.LE_To_UInt32(rand, 0, support);
            Arrays.ZeroMemory(rand);

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
            return support;
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
