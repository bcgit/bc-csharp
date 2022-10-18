using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public class BikeEngine
    {
        // degree of R
        private int r;

        // the row weight
        private int w;

        // Hamming weight of h0, h1
        private int hw;

        // the error weight
        private int t;

        //the shared secret size
        private int l;

        // number of iterations in BGF decoder
        private int nbIter;

        // tau
        private int tau;

        private BikePolynomial reductionPoly;
        private int L_BYTE;
        private int R_BYTE;

        public BikeEngine(int r, int w, int t, int l, int nbIter, int tau)
        {
            this.r = r;
            this.w = w;
            this.t = t;
            this.l = l;
            this.nbIter = nbIter;
            this.tau = tau;
            this.hw = this.w / 2;
            this.L_BYTE = l / 8;
            this.R_BYTE = (r + 7) / 8;

            // generate reductionPoly (X^r + 1)
            this.reductionPoly = new BikePolynomial(r);
        }

        public int GetSessionKeySize()
        {
            return L_BYTE;
        }

        private byte[] FunctionH(byte[] seed)
        {
            IXof digest = new ShakeDigest(256);
            digest.BlockUpdate(seed, 0, seed.Length);
            byte[] wlist = BikeRandomGenerator.GenerateRandomByteArray(r * 2, 2 * R_BYTE, t, digest);
            return wlist;
        }

        private byte[] FunctionL(byte[] e0, byte[] e1)
        {
            byte[] hashRes = new byte[48];
            byte[] res = new byte[L_BYTE];

            
            Sha3Digest digest = new Sha3Digest(384);
            digest.BlockUpdate(e0, 0, e0.Length);
            digest.BlockUpdate(e1, 0, e1.Length);
            digest.DoFinal(hashRes, 0);

            Array.Copy(hashRes, 0, res, 0, L_BYTE);
            return res;
        }

        private byte[] FunctionK(byte[] m, byte[] c0, byte[] c1)
        {
            byte[] hashRes = new byte[48];
            byte[] res = new byte[L_BYTE];

            Sha3Digest digest = new Sha3Digest(384);
            digest.BlockUpdate(m, 0, m.Length);
            digest.BlockUpdate(c0, 0, c0.Length);
            digest.BlockUpdate(c1, 0, c1.Length);
            digest.DoFinal(hashRes, 0);

            Array.Copy(hashRes, 0, res, 0, L_BYTE);
            return res;
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
        public void GenKeyPair(byte[] h0, byte[] h1, byte[] sigma, byte[] h, SecureRandom random)
        {
            //         Randomly generate seeds
            byte[] seeds = new byte[64];
            random.NextBytes(seeds);

            byte[] seed1 = new byte[L_BYTE];
            byte[] seed2 = new byte[L_BYTE];
            Array.Copy(seeds, 0, seed1, 0, seed1.Length);
            Array.Copy(seeds, seed1.Length, seed2, 0, seed2.Length);

            IXof digest = new ShakeDigest(256);
            digest.BlockUpdate(seed1, 0, seed1.Length);

            //      1. Randomly generate h0, h1
            byte[] h0Tmp = BikeRandomGenerator.GenerateRandomByteArray(r, R_BYTE, hw, digest);
            byte[] h1Tmp = BikeRandomGenerator.GenerateRandomByteArray(r, R_BYTE, hw, digest);

            Array.Copy(h0Tmp, 0, h0, 0, h0.Length);
            Array.Copy(h1Tmp, 0, h1, 0, h1.Length);

            byte[] h1Bits = new byte[r];
            byte[] h0Bits = new byte[r];

            Utils.FromByteArrayToBitArray(h0Bits, h0Tmp);
            Utils.FromByteArrayToBitArray(h1Bits, h1Tmp);

            // remove last 0 bits (most significant bits with 0 mean non-sense)
            byte[] h0Cut = Utils.RemoveLast0Bits(h0Bits);
            byte[] h1Cut = Utils.RemoveLast0Bits(h1Bits);

            // 2. Compute h
            BikePolynomial h0Poly = new BikePolynomial(h0Cut);
            BikePolynomial h1Poly = new BikePolynomial(h1Cut);

            BikePolynomial h0Inv = h0Poly.ModInverseBigDeg(reductionPoly);
            BikePolynomial hPoly = h1Poly.ModKaratsubaMultiplyBigDeg(h0Inv, reductionPoly);

            // Get coefficients of hPoly
            byte[] hTmp = hPoly.GetEncoded();
            byte[] hByte = new byte[R_BYTE];
            Utils.FromBitArrayToByteArray(hByte, hTmp);
            Array.Copy(hByte, 0, h, 0, h.Length);

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
        public void Encaps(byte[] c0, byte[] c1, byte[] k, byte[] h, SecureRandom random)
        {
            byte[] seeds = new byte[64];
            random.NextBytes(seeds);

            // 1. Randomly generate m by using seed1
            byte[] m = new byte[L_BYTE];
            Array.Copy(seeds, 0, m, 0, m.Length);

            // 2. Calculate e0, e1
            byte[] eBytes = FunctionH(m);

            byte[] eBits = new byte[2 * r];
            Utils.FromByteArrayToBitArray(eBits, eBytes);

            byte[] e0Bits = Arrays.CopyOfRange(eBits, 0, r);
            byte[] e1Bits = Arrays.CopyOfRange(eBits, r, eBits.Length);

            // remove last 0 bits (most significant bits with 0 mean no sense)
            byte[] e0Cut = Utils.RemoveLast0Bits(e0Bits);
            byte[] e1Cut = Utils.RemoveLast0Bits(e1Bits);

            BikePolynomial e0 = new BikePolynomial(e0Cut);
            BikePolynomial e1 = new BikePolynomial(e1Cut);

            // 3. Calculate c
            // calculate c0
            byte[] h0Bits = new byte[r];
            Utils.FromByteArrayToBitArray(h0Bits, h);
            BikePolynomial hPoly = new BikePolynomial(Utils.RemoveLast0Bits(h0Bits));
            BikePolynomial c0Poly = e0.Add(e1.ModKaratsubaMultiplyBigDeg(hPoly, reductionPoly));

            byte[] c0Bits = c0Poly.GetEncoded();
            byte[] c0Bytes = new byte[R_BYTE];
            Utils.FromBitArrayToByteArray(c0Bytes, c0Bits);
            Array.Copy(c0Bytes, 0, c0, 0, c0.Length);

            //calculate c1
            byte[] e0Bytes = new byte[R_BYTE];
            Utils.FromBitArrayToByteArray(e0Bytes, e0Bits);
            byte[] e1Bytes = new byte[R_BYTE];
            Utils.FromBitArrayToByteArray(e1Bytes, e1Bits);

            byte[] tmp = FunctionL(e0Bytes, e1Bytes);
            byte[] c1Tmp = Utils.XorBytes(m, tmp, L_BYTE);
            Array.Copy(c1Tmp, 0, c1, 0, c1.Length);

            // 4. Calculate K
            byte[] kTmp = FunctionK(m, c0, c1);
            Array.Copy(kTmp, 0, k, 0, kTmp.Length);
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
        public void Decaps(byte[] k, byte[] h0, byte[] h1, byte[] sigma, byte[] c0, byte[] c1)
        {
            //convert to bits
            byte[] c0Bits = new byte[this.r];
            byte[] h0Bits = new byte[this.r];
            byte[] sigmaBits = new byte[this.l];

            Utils.FromByteArrayToBitArray(c0Bits, c0);
            Utils.FromByteArrayToBitArray(h0Bits, h0);
            Utils.FromByteArrayToBitArray(sigmaBits, sigma);

            byte[] c0Cut = Utils.RemoveLast0Bits(c0Bits);
            byte[] h0Cut = Utils.RemoveLast0Bits(h0Bits);

            // Get compact version of h0, h1
            int[] h0Compact = new int[hw];
            int[] h1Compact = new int[hw];
            ConvertToCompact(h0Compact, h0);
            ConvertToCompact(h1Compact, h1);

            // Compute syndrome
            byte[] syndrome = ComputeSyndrome(c0Cut, h0Cut);

            // 1. Compute e'
            byte[] ePrimeBits = BGFDecoder(syndrome, h0Compact, h1Compact);
            byte[] ePrimeBytes = new byte[2 * R_BYTE];
            Utils.FromBitArrayToByteArray(ePrimeBytes, ePrimeBits);

            byte[] e0Bits = Arrays.CopyOfRange(ePrimeBits, 0, r);
            byte[] e1Bits = Arrays.CopyOfRange(ePrimeBits, r, ePrimeBits.Length);

            byte[] e0Bytes = new byte[R_BYTE];
            Utils.FromBitArrayToByteArray(e0Bytes, e0Bits);
            byte[] e1Bytes = new byte[R_BYTE];
            Utils.FromBitArrayToByteArray(e1Bytes, e1Bits);

            // 2. Compute m'
            byte[] mPrime = Utils.XorBytes(c1, FunctionL(e0Bytes, e1Bytes), L_BYTE);

            // 3. Compute K
            byte[] tmpK = new byte[l];
            byte[] wlist = FunctionH(mPrime);
            if (Arrays.AreEqual(ePrimeBytes, wlist))
            {
                tmpK = FunctionK(mPrime, c0, c1);
            }
            else
            {
                tmpK = FunctionK(sigma, c0, c1);
            }
            Array.Copy(tmpK, 0, k, 0, tmpK.Length);
        }

        private byte[] ComputeSyndrome(byte[] h0, byte[] c0)
        {
            BikePolynomial coPoly = new BikePolynomial(c0);
            BikePolynomial h0Poly = new BikePolynomial(h0);

            BikePolynomial s = coPoly.ModKaratsubaMultiplyBigDeg(h0Poly, reductionPoly);
            byte[] transposedS = Transpose(s.GetEncoded());
            return transposedS;
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

                int T = Threshold(Utils.GetHammingWeight(s), i, r);

                BFIter(s, e, T, h0Compact, h1Compact, h0CompactCol, h1CompactCol, black, gray);

                if (i == 1)
                {
                    BFMaskedIter(s, e, black, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
                    BFMaskedIter(s, e, gray, (hw + 1) / 2 + 1, h0Compact, h1Compact, h0CompactCol, h1CompactCol);
                }
            }

            if (Utils.GetHammingWeight(s) == 0)
                return e;

            return null;
        }

        private byte[] Transpose(byte[] input)
        {
            byte[] tmp = Utils.Append0s(input, r); // append zeros to s
            byte[] output = new byte[r];
            output[0] = tmp[0];
            for (int i = 1; i < r; i++)
            {
                output[i] = tmp[r - i];
            }
            return output;
        }

        private void BFIter(byte[] s, byte[] e, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol, int[] h1CompactCol, byte[] black, byte[] gray)
        {
            int[] updatedIndices = new int[2 * r];

            // calculate for h0compact
            for (int j = 0; j < r; j++)
            {
                if (Ctr(h0CompactCol, s, j) >= T)
                {
                    UpdateNewErrorIndex(e, j);
                    updatedIndices[j] = 1;
                    black[j] = 1;
                }
                else if (Ctr(h0CompactCol, s, j) >= T - tau)
                {
                    gray[j] = 1;
                }
            }

            // calculate for h1Compact
            for (int j = 0; j < r; j++)
            {
                if (Ctr(h1CompactCol, s, j) >= T)
                {
                    UpdateNewErrorIndex(e, r + j);
                    updatedIndices[r + j] = 1;
                    black[r + j] = 1;
                }
                else if (Ctr(h1CompactCol, s, j) >= T - tau)
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

        private void BFMaskedIter(byte[] s, byte[] e, byte[] mask, int T, int[] h0Compact, int[] h1Compact, int[] h0CompactCol, int[] h1CompactCol)
        {
            int[] updatedIndices = new int[2 * r];

            for (int j = 0; j < r; j++)
            {
                if (Ctr(h0CompactCol, s, j) >= T && mask[j] == 1)
                {
                    UpdateNewErrorIndex(e, j);
                    updatedIndices[j] = 1;
                }
            }

            for (int j = 0; j < r; j++)
            {
                if (Ctr(h1CompactCol, s, j) >= T && mask[r + j] == 1)
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

        private int Threshold(int hammingWeight, int i, int r)
        {
            double d = 0;
            int floorD = 0;
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
            int count = 0;
            for (int i = 0; i < hw; i++)
            {
                if (s[(hCompactCol[i] + j) % r] == 1)
                {
                    count += 1;
                }
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
                    {
                        break;
                    }

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
