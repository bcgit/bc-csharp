using System;
using System.Diagnostics;
#if NETCOREAPP1_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Numerics;
#endif

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal sealed class BikeEngine
    {
        // degree of R
        private readonly int r;

        // the row weight
        private readonly int w;

        // Hamming weight of h0, h1
        private readonly int hw;

        // the error weight
        private readonly int t;

        //the shared secret size
        //private readonly int l;

        // number of iterations in BGF decoder
        private readonly int nbIter;

        // tau
        private readonly int tau;

        private readonly BikeRing bikeRing;
        private readonly int L_BYTE;
        private readonly int R_BYTE;
        private readonly int R2_UINT;
        private readonly int R_ULONG;
        private readonly int R2_ULONG;

        internal BikeEngine(int r, int w, int t, int l, int nbIter, int tau)
        {
            this.r = r;
            this.w = w;
            this.t = t;
            //this.l = l;
            this.nbIter = nbIter;
            this.tau = tau;
            this.hw = this.w / 2;
            this.L_BYTE = l / 8;
            this.R_BYTE = (r + 7) >> 3;
            this.R2_UINT = (2 * r + 31) >> 5;
            this.R_ULONG = (r + 63) >> 6;
            this.R2_ULONG = (2 * r + 63) >> 6;
            this.bikeRing = new BikeRing(r);
        }

        internal int SessionKeySize => L_BYTE;

        private ulong[] FunctionH(byte[] seed)
        {
            IXof digest = new ShakeDigest(256);
            digest.BlockUpdate(seed, 0, seed.Length);
            ulong[] res = new ulong[2 * R_ULONG];
            BikeUtilities.GenerateRandomUlongs(res, 2 * r, t, digest);
            return res;
        }

        private void FunctionL(ulong[] e01, byte[] c1, int c1Off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> hashRes = stackalloc byte[48];
            Sha3Digest.CalculateDigest(e01, 16 * R_BYTE, hashRes, 384);
            hashRes[..L_BYTE].CopyTo(c1.AsSpan(c1Off));
#else
            byte[] hashRes = new byte[48];
            Sha3Digest.CalculateDigest(e01, 0, 16 * R_BYTE, hashRes, 0, 384);
            Array.Copy(hashRes, 0, c1, c1Off, L_BYTE);
#endif
        }

        private void FunctionK(byte[] m, byte[] c01, byte[] result)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> hashRes = stackalloc byte[48];

            var digest = new Sha3Digest(384);
            digest.BlockUpdate(m);
            digest.BlockUpdate(c01);
            digest.DoFinal(hashRes);

            hashRes[..L_BYTE].CopyTo(result);
#else
            byte[] hashRes = new byte[48];

            var digest = new Sha3Digest(384);
            digest.BlockUpdate(m, 0, m.Length);
            digest.BlockUpdate(c01, 0, c01.Length);
            digest.DoFinal(hashRes, 0);

            Array.Copy(hashRes, 0, result, 0, L_BYTE);
#endif
        }

        private void FunctionK(byte[] m, byte[] c0, byte[] c1, byte[] result)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> hashRes = stackalloc byte[48];

            var digest = new Sha3Digest(384);
            digest.BlockUpdate(m);
            digest.BlockUpdate(c0);
            digest.BlockUpdate(c1);
            digest.DoFinal(hashRes);

            hashRes[..L_BYTE].CopyTo(result);
#else
            byte[] hashRes = new byte[48];

            var digest = new Sha3Digest(384);
            digest.BlockUpdate(m, 0, m.Length);
            digest.BlockUpdate(c0, 0, c0.Length);
            digest.BlockUpdate(c1, 0, c1.Length);
            digest.DoFinal(hashRes, 0);

            Array.Copy(hashRes, 0, result, 0, L_BYTE);
#endif
        }

        /**
         Generate key pairs
         - Secret key : (h0, h1, sigma)
         - Public key: h
         * @param h0            h0
         * @param h1            h1
         * @param sigma         sigma
         * @param h             h
         * @param random        Secure Random
         **/
        internal void GenKeyPair(byte[] h0, byte[] h1, byte[] sigma, byte[] h, SecureRandom random)
        {
            // Randomly generate seeds
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> seeds = stackalloc byte[64];
#else
            byte[] seeds = new byte[64];
#endif
            random.NextBytes(seeds);

            IXof digest = new ShakeDigest(256);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            digest.BlockUpdate(seeds[..L_BYTE]);
#else
            digest.BlockUpdate(seeds, 0, L_BYTE);
#endif

            // 1. Randomly generate h0, h1
            ulong[] h0Element = bikeRing.Create();
            ulong[] h1Element = bikeRing.Create();
            BikeUtilities.GenerateRandomUlongs(h0Element, r, hw, digest);
            BikeUtilities.GenerateRandomUlongs(h1Element, r, hw, digest);
            bikeRing.EncodeBytes(h0Element, h0);
            bikeRing.EncodeBytes(h1Element, h1);

            // 2. Compute h
            bikeRing.Inv(h0Element, h0Element);
            bikeRing.Multiply(h0Element, h1Element, h0Element);
            bikeRing.EncodeBytes(h0Element, h);

            //3. Parse seed2 as sigma
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            sigma.AsSpan().CopyFrom(seeds[L_BYTE..]);
#else
            Array.Copy(seeds, L_BYTE, sigma, 0, sigma.Length);
#endif
        }

        /**
         KEM Encapsulation
         - Input: h
         - Output: (c0,c1,k)
         * @param c0            ciphertext
         * @param c1            ciphertext
         * @param k             session key
         * @param h             public key
         * @param random        Secure Random
         **/
        internal void Encaps(byte[] c01, byte[] k, byte[] h, SecureRandom random)
        {
            // 1. Randomly generate m by using seed1
            byte[] m = new byte[L_BYTE];
            random.NextBytes(m);

            // 2. Calculate e0, e1
            ulong[] e01 = FunctionH(m);

            // 3. Calculate c
            AlignE01From1To64(e01);
            ulong[] t = bikeRing.Create();
            bikeRing.DecodeBytes(h, t);
            bikeRing.Multiply(t, 0, e01, R_ULONG, t);
            bikeRing.Add(t, e01, t);
            bikeRing.EncodeBytes(t, c01);

            //calculate c1
            AlignE01From64To8(e01);
            FunctionL(e01, c01, R_BYTE);
            Bytes.XorTo(L_BYTE, m, 0, c01, R_BYTE);

            // 4. Calculate K
            FunctionK(m, c01, k);
        }

        /**
         KEM Decapsulation
         - Input: (h0, h1, sigma), (c0, c1)
         - Output: k
         * @param h0            private key
         * @param h1            private key
         * @param sigma         private key
         * @param c0            ciphertext
         * @param c1            ciphertext
         * @param k             session key
         **/
        internal void Decaps(byte[] k, byte[] h0, byte[] h1, byte[] sigma, byte[] c0, byte[] c1)
        {
            // Get compact version of h0, h1
            int[] h0Compact = new int[hw];
            int[] h1Compact = new int[hw];
            ConvertToCompact(h0Compact, h0);
            ConvertToCompact(h1Compact, h1);

            // Compute syndrome
            byte[] syndromeBits = ComputeSyndrome(c0, h0);

            // 1. Compute e'
            // TODO Produce e01 directly
            byte[] ePrimeBits = BGFDecoder(syndromeBits, h0Compact, h1Compact);
            ulong[] e01 = new ulong[2 * R_ULONG];
            BikeUtilities.FromBitsToUlongs(e01, ePrimeBits, 0, 2 * r);

            // 2. Compute m'
            // TODO Merge (or produce aligned to 64)
            AlignE01From1To64(e01);
            AlignE01From64To8(e01);
            byte[] mPrime = new byte[L_BYTE];
            FunctionL(e01, mPrime, 0);
            Bytes.XorTo(L_BYTE, c1, mPrime);

            // 3. Compute K
            AlignE01From8To1(e01);
            ulong[] wlist = FunctionH(mPrime);
            if (Arrays.AreEqual(e01, 0, R2_ULONG, wlist, 0, R2_ULONG))
            {
                FunctionK(mPrime, c0, c1, k);
            }
            else
            {
                FunctionK(sigma, c0, c1, k);
            }
        }

        private byte[] ComputeSyndrome(byte[] c0, byte[] h0)
        {
            ulong[] t = bikeRing.Create();
            ulong[] u = bikeRing.Create();
            bikeRing.DecodeBytes(c0, t);
            bikeRing.DecodeBytes(h0, u);
            bikeRing.Multiply(t, u, t);
            return bikeRing.EncodeBitsTransposed(t);
        }

        private byte[] BGFDecoder(byte[] s, int[] h0Compact, int[] h1Compact)
        {
            byte[] e = new byte[2 * r];

            // Get compact column version
            int[] h0CompactCol = GetColumnFromCompactVersion(h0Compact);
            int[] h1CompactCol = GetColumnFromCompactVersion(h1Compact);

            uint[] black = new uint[R2_UINT];
            byte[] ctrs = new byte[r];

            {
                uint[] gray = new uint[R2_UINT];

                int T = Threshold(BikeUtilities.GetHammingWeight(s), r);

                BFIter(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, black, gray, ctrs);
                BFMaskedIter(s, e, black, (hw + 3) / 2, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
                BFMaskedIter(s, e, gray, (hw + 3) / 2, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
            }
            for (int i = 1; i < nbIter; i++)
            {
                Array.Clear(black, 0, black.Length);

                int T = Threshold(BikeUtilities.GetHammingWeight(s), r);

                BFIter2(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, black, ctrs);
            }

            if (BikeUtilities.GetHammingWeight(s) == 0)
                return e;

            return null;
        }

        private void BFIter(byte[] s, byte[] e, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol,
            int[] h1CompactCol, uint[] black, uint[] gray, byte[] ctrs)
        {
            // calculate for h0compact
            {
                CtrAll(h0CompactCol, s, ctrs);

                {
                    int ctrBit1 = ((ctrs[0] - T) >> 31) + 1;
                    int ctrBit2 = ((ctrs[0] - (T - tau)) >> 31) + 1;
                    e[0] ^= (byte)ctrBit1;
                    black[0] |= (uint)ctrBit1;
                    gray[0] |= (uint)ctrBit2;
                }
                for (int j = 1; j < r; j++)
                {
                    int ctrBit1 = ((ctrs[j] - T) >> 31) + 1;
                    int ctrBit2 = ((ctrs[j] - (T - tau)) >> 31) + 1;
                    e[r - j] ^= (byte)ctrBit1;
                    black[j >> 5] |= (uint)ctrBit1 << (j & 31);
                    gray[j >> 5] |= (uint)ctrBit2 << (j & 31);
                }
            }

            // calculate for h1Compact
            {
                CtrAll(h1CompactCol, s, ctrs);

                {
                    int ctrBit1 = ((ctrs[0] - T) >> 31) + 1;
                    int ctrBit2 = ((ctrs[0] - (T - tau)) >> 31) + 1;
                    e[r] ^= (byte)ctrBit1;
                    black[r >> 5] |= (uint)ctrBit1 << (r & 31);
                    gray[r >> 5] |= (uint)ctrBit2 << (r & 31);
                }
                for (int j = 1; j < r; j++)
                {
                    int ctrBit1 = ((ctrs[j] - T) >> 31) + 1;
                    int ctrBit2 = ((ctrs[j] - (T - tau)) >> 31) + 1;
                    e[r + r - j] ^= (byte)ctrBit1;
                    black[(r + j) >> 5] |= (uint)ctrBit1 << ((r + j) & 31);
                    gray[(r + j) >> 5] |= (uint)ctrBit2 << ((r + j) & 31);
                }
            }

            // recompute syndrome
            for (int i = 0; i < black.Length; ++i)
            {
                uint bits = black[i];
                while (bits != 0)
                {
                    int tz = Integers.NumberOfTrailingZeros((int)bits);
                    RecomputeSyndrome(s, (i << 5) + tz, h0Compact, h1Compact);
                    bits ^= 1U << tz;
                }
            }
        }

        private void BFIter2(byte[] s, byte[] e, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol,
            int[] h1CompactCol, uint[] black, byte[] ctrs)
        {
            // calculate for h0compact
            {
                CtrAll(h0CompactCol, s, ctrs);

                {
                    int ctrBit1 = ((ctrs[0] - T) >> 31) + 1;
                    e[0] ^= (byte)ctrBit1;
                    black[0] |= (uint)ctrBit1;
                }
                for (int j = 1; j < r; j++)
                {
                    int ctrBit1 = ((ctrs[j] - T) >> 31) + 1;
                    e[r - j] ^= (byte)ctrBit1;
                    black[j >> 5] |= (uint)ctrBit1 << (j & 31);
                }
            }

            // calculate for h1compact
            {
                CtrAll(h1CompactCol, s, ctrs);

                {
                    int ctrBit1 = ((ctrs[0] - T) >> 31) + 1;
                    e[r] ^= (byte)ctrBit1;
                    black[r >> 5] |= (uint)ctrBit1 << (r & 31);
                }
                for (int j = 1; j < r; j++)
                {
                    int ctrBit1 = ((ctrs[j] - T) >> 31) + 1;
                    e[r + r - j] ^= (byte)ctrBit1;
                    black[(r + j) >> 5] |= (uint)ctrBit1 << ((r + j) & 31);
                }
            }

            // recompute syndrome
            for (int i = 0; i < black.Length; ++i)
            {
                uint bits = black[i];
                while (bits != 0)
                {
                    int tz = Integers.NumberOfTrailingZeros((int)bits);
                    RecomputeSyndrome(s, (i << 5) + tz, h0Compact, h1Compact);
                    bits ^= 1U << tz;
                }
            }
        }

        private void BFMaskedIter(byte[] s, byte[] e, uint[] mask, int T, int[] h0Compact, int[] h1Compact,
            int[] h0CompactCol, int[] h1CompactCol)
        {
            uint[] updatedIndices = new uint[R2_UINT];

            for (int j = 0; j < r; j++)
            {
                if ((mask[j >> 5] & (1U << (j & 31))) != 0)
                {
                    int ctr = Ctr(h0CompactCol, s, j);
                    int ctrBit1 = ((ctr - T) >> 31) + 1;

                    int k = -j;
                    k += (k >> 31) & r;
                    e[k] ^= (byte)ctrBit1;

                    updatedIndices[j >> 5] |= (uint)ctrBit1 << (j & 31);
                }
            }

            for (int j = 0; j < r; j++)
            {
                if ((mask[(r + j) >> 5] & (1U << ((r + j) & 31))) != 0)
                {
                    int ctr = Ctr(h1CompactCol, s, j);
                    int ctrBit1 = ((ctr - T) >> 31) + 1;

                    int k = -j;
                    k += (k >> 31) & r;
                    e[r + k] ^= (byte)ctrBit1;

                    updatedIndices[(r + j) >> 5] |= (uint)ctrBit1 << ((r + j) & 31);
                }
            }

            // recompute syndrome
            for (int i = 0; i < updatedIndices.Length; ++i)
            {
                uint bits = updatedIndices[i];
                while (bits != 0)
                {
                    int tz = Integers.NumberOfTrailingZeros((int)bits);
                    RecomputeSyndrome(s, (i << 5) + tz, h0Compact, h1Compact);
                    bits ^= 1U << tz;
                }
            }
        }

        private static int Threshold(int hammingWeight, int r)
        {
            switch (r)
            {
            case 12323: return ThresholdFromParameters(hammingWeight, 0.0069722, 13.530, 36);
            case 24659: return ThresholdFromParameters(hammingWeight, 0.005265, 15.2588, 52);
            case 40973: return ThresholdFromParameters(hammingWeight, 0.00402312, 17.8785, 69);
            default:    throw new ArgumentException();
            }
        }

        private static int ThresholdFromParameters(int hammingWeight, double dm, double da, int min)
        {
            return System.Math.Max(min, Convert.ToInt32(System.Math.Floor(dm * hammingWeight + da)));
        }

        private int Ctr(int[] hCompactCol, byte[] s, int j)
        {
            Debug.Assert(0 <= j && j < r);

            int count = 0;

            int i = 0, limit = hw - 4;
            while (i <= limit)
            {
                int sPos0 = hCompactCol[i + 0] + j - r;
                int sPos1 = hCompactCol[i + 1] + j - r;
                int sPos2 = hCompactCol[i + 2] + j - r;
                int sPos3 = hCompactCol[i + 3] + j - r;

                sPos0 += (sPos0 >> 31) & r;
                sPos1 += (sPos1 >> 31) & r;
                sPos2 += (sPos2 >> 31) & r;
                sPos3 += (sPos3 >> 31) & r;

                count += s[sPos0];
                count += s[sPos1];
                count += s[sPos2];
                count += s[sPos3];

                i += 4;
            }
            while (i < hw)
            {
                int sPos = hCompactCol[i] + j - r;
                sPos += (sPos >> 31) & r;
                count += s[sPos];
                ++i;
            }
            return count;
        }

        private void CtrAll(int[] hCompactCol, byte[] s, byte[] ctrs)
        {
            {
                int col = hCompactCol[0], neg = r - col;
                Array.Copy(s, col, ctrs, 0, neg);
                Array.Copy(s, 0, ctrs, neg, col);
            }
            for (int i = 1; i < hw; ++i)
            {
                int col = hCompactCol[i], neg = r - col;

                int j = 0;
#if NETCOREAPP1_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                if (Vector.IsHardwareAccelerated)
                {
                    int jLimit = neg - Vector<byte>.Count;
                    while (j <= jLimit)
                    {
                        var vc = new Vector<byte>(ctrs, j);
                        var vs = new Vector<byte>(s, col + j);
                        (vc + vs).CopyTo(ctrs, j);
                        j += Vector<byte>.Count;
                    }
                }
#endif
                {
                    int jLimit = neg - 4;
                    while (j <= jLimit)
                    {
                        ctrs[j + 0] += s[col + j + 0];
                        ctrs[j + 1] += s[col + j + 1];
                        ctrs[j + 2] += s[col + j + 2];
                        ctrs[j + 3] += s[col + j + 3];
                        j += 4;
                    }
                }
                {
                    while (j < neg)
                    {
                        ctrs[j] += s[col + j];
                        ++j;
                    }
                }

                int k = neg;
#if NETCOREAPP1_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                if (Vector.IsHardwareAccelerated)
                {
                    int kLimit = r - Vector<byte>.Count;
                    while (k <= kLimit)
                    {
                        var vc = new Vector<byte>(ctrs, k);
                        var vs = new Vector<byte>(s, k - neg);
                        (vc + vs).CopyTo(ctrs, k);
                        k += Vector<byte>.Count;
                    }
                }
#endif
                {
                    int kLimit = r - 4;
                    while (k <= kLimit)
                    {
                        ctrs[k + 0] += s[k + 0 - neg];
                        ctrs[k + 1] += s[k + 1 - neg];
                        ctrs[k + 2] += s[k + 2 - neg];
                        ctrs[k + 3] += s[k + 3 - neg];
                        k += 4;
                    }
                }
                {
                    while (k < r)
                    {
                        ctrs[k] += s[k - neg];
                        ++k;
                    }
                }
            }
        }

        // Convert a polynomial in GF2 to an array of positions of which the coefficients of the polynomial are equals to 1
        private void ConvertToCompact(int[] compactVersion, byte[] h)
        {
            // maximum size of this array is the Hamming weight of the polynomial
            int count = 0;
            for (int i = 0; i < R_BYTE; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    if ((i * 8 + j) == this.r)
                        break;

                    if (((h[i] >> j) & 1) == 1)
                    {
                        compactVersion[count++] = i * 8 + j;
                    }
                }
            }
        }

        private int[] GetColumnFromCompactVersion(int[] hCompact)
        {
            int[] hCompactColumn = new int[hw];
            if (hCompact[0] == 0)
            {
                hCompactColumn[0] = 0;
                for (int i = 1; i < hw; i++)
                {
                    hCompactColumn[i] = r - hCompact[hw - i];
                }
            }
            else
            {
                for (int i = 0; i < hw; i++)
                {
                    hCompactColumn[i] = r - hCompact[hw - 1 - i];
                }
            }
            return hCompactColumn;
        }

        private void RecomputeSyndrome(byte[] syndrome, int index, int[] h0Compact, int[] h1Compact)
        {
            if (index < r)
            {
                for (int i = 0; i < hw; i++)
                {
                    if (h0Compact[i] <= index)
                    {
                        syndrome[index - h0Compact[i]] ^= 1;
                    }
                    else
                    {
                        syndrome[r + index - h0Compact[i]] ^= 1;
                    }
                }
            }
            else
            {
                for (int i = 0; i < hw; i++)
                {
                    if (h1Compact[i] <= (index - r))
                    {
                        syndrome[(index - r) - h1Compact[i]] ^= 1;
                    }
                    else
                    {
                        syndrome[r - h1Compact[i] + (index - r)] ^= 1;
                    }
                }
            }
        }

        private void AlignE01From1To64(ulong[] e01)
        {
            int partial = r & 63;
            int shift = 64 - partial;
            ulong mask = ulong.MaxValue << partial;
            Debug.Assert(partial != 0);
            Debug.Assert(shift != 0);

            ulong split = e01[R_ULONG - 1];
            ulong c = split & mask;
            Nat.ShiftUpBits64(R_ULONG, e01, R_ULONG, shift, c);
            e01[R_ULONG - 1] = split & ~mask;
        }

        private void AlignE01From64To8(ulong[] e01)
        {
            int partial = (8 * R_BYTE) & 63;
            int shift = 64 - partial;
            ulong mask = ulong.MaxValue << partial;
            Debug.Assert(partial != 0);
            Debug.Assert(shift != 0);

            ulong c = Nat.ShiftDownBits64(R_ULONG, e01, R_ULONG, shift, 0UL);
            e01[R_ULONG - 1] |= c;
        }

        private void AlignE01From8To1(ulong[] e01)
        {
            int partial = r & 63;
            int shift = 8 * R_BYTE - r;
            ulong mask = ulong.MaxValue << partial;
            Debug.Assert(partial != 0);
            Debug.Assert(shift != 0);

            ulong split = e01[R_ULONG - 1];
            ulong c = Nat.ShiftDownBits64(R_ULONG, e01, R_ULONG, shift, 0UL);
            e01[R_ULONG - 1] = (split & ~mask) | ((split >> shift) & mask) | c;
        }
    }
}
