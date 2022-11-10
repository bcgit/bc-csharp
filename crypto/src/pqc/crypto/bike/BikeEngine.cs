using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
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
            this.R_BYTE = (r + 7) / 8;
            this.bikeRing = new BikeRing(r);
        }

        internal int SessionKeySize => L_BYTE;

        private byte[] FunctionH(byte[] seed)
        {
            IXof digest = new ShakeDigest(256);
            digest.BlockUpdate(seed, 0, seed.Length);
            return BikeUtilities.GenerateRandomByteArray(r * 2, 2 * R_BYTE, t, digest);
        }

        private void FunctionL(byte[] e0, byte[] e1, byte[] result)
        {
            byte[] hashRes = new byte[48];

            Sha3Digest digest = new Sha3Digest(384);
            digest.BlockUpdate(e0, 0, e0.Length);
            digest.BlockUpdate(e1, 0, e1.Length);
            digest.DoFinal(hashRes, 0);

            Array.Copy(hashRes, 0, result, 0, L_BYTE);
        }

        private void FunctionK(byte[] m, byte[] c0, byte[] c1, byte[] result)
        {
            byte[] hashRes = new byte[48];

            Sha3Digest digest = new Sha3Digest(384);
            digest.BlockUpdate(m, 0, m.Length);
            digest.BlockUpdate(c0, 0, c0.Length);
            digest.BlockUpdate(c1, 0, c1.Length);
            digest.DoFinal(hashRes, 0);

            Array.Copy(hashRes, 0, result, 0, L_BYTE);
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
            byte[] seeds = new byte[64];
            random.NextBytes(seeds);

            byte[] seed1 = new byte[L_BYTE];
            byte[] seed2 = new byte[L_BYTE];
            Array.Copy(seeds, 0, seed1, 0, seed1.Length);
            Array.Copy(seeds, seed1.Length, seed2, 0, seed2.Length);

            IXof digest = new ShakeDigest(256);
            digest.BlockUpdate(seed1, 0, seed1.Length);

            // 1. Randomly generate h0, h1
            ulong[] h0Element = bikeRing.GenerateRandom(hw, digest);
            ulong[] h1Element = bikeRing.GenerateRandom(hw, digest);

            bikeRing.EncodeBytes(h0Element, h0);
            bikeRing.EncodeBytes(h1Element, h1);

            // 2. Compute h
            ulong[] hElement = bikeRing.Create();
            bikeRing.Inv(h0Element, hElement);
            bikeRing.Multiply(hElement, h1Element, hElement);
            bikeRing.EncodeBytes(hElement, h);

            //3. Parse seed2 as sigma
            Array.Copy(seed2, 0, sigma, 0, sigma.Length);
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
        internal void Encaps(byte[] c0, byte[] c1, byte[] k, byte[] h, SecureRandom random)
        {
            byte[] seeds = new byte[64];
            random.NextBytes(seeds);

            // 1. Randomly generate m by using seed1
            byte[] m = new byte[L_BYTE];
            Array.Copy(seeds, 0, m, 0, m.Length);

            // 2. Calculate e0, e1
            byte[] eBytes = FunctionH(m);

            byte[] eBits = new byte[2 * r];
            BikeUtilities.FromByteArrayToBitArray(eBits, eBytes);

            byte[] e0Bits = Arrays.CopyOfRange(eBits, 0, r);
            byte[] e0Bytes = new byte[R_BYTE];
            BikeUtilities.FromBitArrayToByteArray(e0Bytes, e0Bits);

            byte[] e1Bits = Arrays.CopyOfRange(eBits, r, eBits.Length);
            byte[] e1Bytes = new byte[R_BYTE];
            BikeUtilities.FromBitArrayToByteArray(e1Bytes, e1Bits);

            ulong[] e0Element = bikeRing.Create();
            ulong[] e1Element = bikeRing.Create();

            bikeRing.DecodeBytes(e0Bytes, e0Element);
            bikeRing.DecodeBytes(e1Bytes, e1Element);

            ulong[] hElement = bikeRing.Create();
            bikeRing.DecodeBytes(h, hElement);

            // 3. Calculate c
            // calculate c0
            ulong[] c0Element = bikeRing.Create();
            bikeRing.Multiply(e1Element, hElement, c0Element);
            bikeRing.Add(c0Element, e0Element, c0Element);
            bikeRing.EncodeBytes(c0Element, c0);

            //calculate c1
            FunctionL(e0Bytes, e1Bytes, c1);
            BikeUtilities.XorTo(m, c1, L_BYTE);

            // 4. Calculate K
            FunctionK(m, c0, c1, k);
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
            byte[] ePrimeBits = BGFDecoder(syndromeBits, h0Compact, h1Compact);
            byte[] ePrimeBytes = new byte[2 * R_BYTE];
            BikeUtilities.FromBitArrayToByteArray(ePrimeBytes, ePrimeBits);

            byte[] e0Bits = Arrays.CopyOfRange(ePrimeBits, 0, r);
            byte[] e1Bits = Arrays.CopyOfRange(ePrimeBits, r, ePrimeBits.Length);

            byte[] e0Bytes = new byte[R_BYTE];
            BikeUtilities.FromBitArrayToByteArray(e0Bytes, e0Bits);
            byte[] e1Bytes = new byte[R_BYTE];
            BikeUtilities.FromBitArrayToByteArray(e1Bytes, e1Bits);

            // 2. Compute m'
            byte[] mPrime = new byte[L_BYTE];
            FunctionL(e0Bytes, e1Bytes, mPrime);
            BikeUtilities.XorTo(c1, mPrime, L_BYTE);

            // 3. Compute K
            byte[] wlist = FunctionH(mPrime);
            if (Arrays.AreEqual(ePrimeBytes, wlist))
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
            ulong[] c0Element = bikeRing.Create();
            ulong[] h0Element = bikeRing.Create();
            bikeRing.DecodeBytes(c0, c0Element);
            bikeRing.DecodeBytes(h0, h0Element);
            ulong[] sElement = bikeRing.Create();
            bikeRing.Multiply(c0Element, h0Element, sElement);
            return Transpose(bikeRing.EncodeBits(sElement));
        }

        private byte[] BGFDecoder(byte[] s, int[] h0Compact, int[] h1Compact)
        {
            byte[] e = new byte[2 * r];

            // Get compact column version
            int[] h0CompactCol = GetColumnFromCompactVersion(h0Compact);
            int[] h1CompactCol = GetColumnFromCompactVersion(h1Compact);

            for (int i = 1; i <= nbIter; i++)
            {
                byte[] black = new byte[2 * r];
                byte[] gray = new byte[2 * r];

                int T = Threshold(BikeUtilities.GetHammingWeight(s), r);

                BFIter(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, black, gray);

                if (i == 1)
                {
                    BFMaskedIter(s, e, black, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
                    BFMaskedIter(s, e, gray, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
                }
            }

            if (BikeUtilities.GetHammingWeight(s) == 0)
                return e;

            return null;
        }

        private byte[] Transpose(byte[] input)
        {
            byte[] output = new byte[r];
            output[0] = input[0];
            for (int i = 1; i < r; i++)
            {
                output[i] = input[r - i];
            }
            return output;
        }

        private void BFIter(byte[] s, byte[] e, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol,
            int[] h1CompactCol, byte[] black, byte[] gray)
        {
            int[] updatedIndices = new int[2 * r];

            // calculate for h0compact
            for (int j = 0; j < r; j++)
            {
                int ctr = Ctr(h0CompactCol, s, j);
                if (ctr >= T)
                {
                    UpdateNewErrorIndex(e, j);
                    updatedIndices[j] = 1;
                    black[j] = 1;
                }
                else if (ctr >= T - tau)
                {
                    gray[j] = 1;
                }
            }

            // calculate for h1Compact
            for (int j = 0; j < r; j++)
            {
                int ctr = Ctr(h1CompactCol, s, j);
                if (ctr >= T)
                {
                    UpdateNewErrorIndex(e, r + j);
                    updatedIndices[r + j] = 1;
                    black[r + j] = 1;
                }
                else if (ctr >= T - tau)
                {
                    gray[r + j] = 1;
                }
            }

            // recompute syndrome
            for (int i = 0; i < 2 * r; i++)
            {
                if (updatedIndices[i] == 1)
                {
                    RecomputeSyndrome(s, i, h0Compact, h1Compact);
                }
            }
        }

        private void BFMaskedIter(byte[] s, byte[] e, byte[] mask, int T, int[] h0Compact, int[] h1Compact,
            int[] h0CompactCol, int[] h1CompactCol)
        {
            int[] updatedIndices = new int[2 * r];

            for (int j = 0; j < r; j++)
            {
                if (mask[j] == 1 && Ctr(h0CompactCol, s, j) >= T)
                {
                    UpdateNewErrorIndex(e, j);
                    updatedIndices[j] = 1;
                }
            }

            for (int j = 0; j < r; j++)
            {
                if (mask[r + j] == 1 && Ctr(h1CompactCol, s, j) >= T)
                {
                    UpdateNewErrorIndex(e, r + j);
                    updatedIndices[r + j] = 1;
                }
            }

            // recompute syndrome
            for (int i = 0; i < 2 * r; i++)
            {
                if (updatedIndices[i] == 1)
                {
                    RecomputeSyndrome(s, i, h0Compact, h1Compact);
                }
            }
        }

        private int Threshold(int hammingWeight, int r)
        {
            double d;
            int floorD;
            int res = 0;
            switch (r)
            {
            case 12323:
                d = 0.0069722 * hammingWeight + 13.530;
                floorD = (int) System.Math.Floor(d);
                res = floorD > 36 ? floorD : 36;
                break;
            case 24659:
                d = 0.005265 * hammingWeight + 15.2588;
                floorD = (int) System.Math.Floor(d);
                res = floorD > 52 ? floorD : 52;
                break;
            case 40973:
                d = 0.00402312 * hammingWeight + 17.8785;
                floorD = (int) System.Math.Floor(d);
                res = floorD > 69 ? floorD : 69;
                break;
            }
            return res;
        }

        private int Ctr(int[] hCompactCol, byte[] s, int j)
        {
            Debug.Assert(0 <= j && j < r);

            int count = 0;

            int i = 0, limit8 = hw - 8;
            while (i < limit8)
            {
                int sPos0 = hCompactCol[i + 0] + j - r;
                int sPos1 = hCompactCol[i + 1] + j - r;
                int sPos2 = hCompactCol[i + 2] + j - r;
                int sPos3 = hCompactCol[i + 3] + j - r;
                int sPos4 = hCompactCol[i + 4] + j - r;
                int sPos5 = hCompactCol[i + 5] + j - r;
                int sPos6 = hCompactCol[i + 6] + j - r;
                int sPos7 = hCompactCol[i + 7] + j - r;

                sPos0 += (sPos0 >> 31) & r;
                sPos1 += (sPos1 >> 31) & r;
                sPos2 += (sPos2 >> 31) & r;
                sPos3 += (sPos3 >> 31) & r;
                sPos4 += (sPos4 >> 31) & r;
                sPos5 += (sPos5 >> 31) & r;
                sPos6 += (sPos6 >> 31) & r;
                sPos7 += (sPos7 >> 31) & r;

                count += s[sPos0];
                count += s[sPos1];
                count += s[sPos2];
                count += s[sPos3];
                count += s[sPos4];
                count += s[sPos5];
                count += s[sPos6];
                count += s[sPos7];

                i += 8;
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

        private void UpdateNewErrorIndex(byte[] e, int index)
        {
            int newIndex = index;
            if (index != 0 && index != r)
            {
                if (index > r)
                {
                    newIndex = 2 * r - index + r;
                }
                else
                {
                    newIndex = r - index;
                }
            }
            e[newIndex] ^= 1;
        }
    }
}
