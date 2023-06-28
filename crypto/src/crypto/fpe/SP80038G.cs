using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Fpe
{
    /*
	 * SP800-38G Format-Preserving Encryption
	 *
	 * TODOs
	 * - Initialize the cipher internally or externally?
	 *     1. Algs 7-10 don't appear to require forward vs. inverse transform, although sample data is forward.
	 *     2. Algs 9-10 specify reversal of the cipher key!
	 * - Separate construction/initialization stage for "prerequisites"
	 */
    internal static class SP80038G
    {
        internal static readonly string FPE_DISABLED = "Org.BouncyCastle.Fpe.Disable";
        internal static readonly string FF1_DISABLED = "Org.BouncyCastle.Fpe.Disable_Ff1";

        private static readonly int BLOCK_SIZE = 16;
        private static readonly double LOG2 = System.Math.Log(2.0);
        private static readonly double TWO_TO_96 = System.Math.Pow(2, 96);

        public static byte[] DecryptFF1(IBlockCipher cipher, int radix, byte[] tweak, byte[] buf, int off, int len)
        {
            CheckArgs(cipher, true, radix, buf, off, len);

            // Algorithm 8
            int n = len;
            int u = n / 2, v = n - u;

            ushort[] A = ToShort(buf, off, u);
            ushort[] B = ToShort(buf, off + u, v);

            ushort[] rv = DecFF1(cipher, radix, tweak, n, u, v, A, B);

            return ToByte(rv);
        }

        public static ushort[] DecryptFF1w(IBlockCipher cipher, int radix, byte[] tweak, ushort[] buf, int off, int len)
        {
            CheckArgs(cipher, true, radix, buf, off, len);

            // Algorithm 8
            int n = len;
            int u = n / 2, v = n - u;

            ushort[] A = new ushort[u];
            ushort[] B = new ushort[v];

            Array.Copy(buf, off, A, 0, u);
            Array.Copy(buf, off + u, B, 0, v);

            return DecFF1(cipher, radix, tweak, n, u, v, A, B);
        }

        private static ushort[] DecFF1(IBlockCipher cipher, int radix, byte[] T, int n, int u, int v, ushort[] A, ushort[] B)
        {
            int t = T.Length;
            int b = CalculateB_FF1(radix, v);
            int d = (b + 7) & ~3;

            byte[] P = CalculateP_FF1(radix, (byte)u, n, t);

            BigInteger bigRadix = BigInteger.ValueOf(radix);
            BigInteger[] modUV = CalculateModUV(bigRadix, u, v);

            int m = u;

            for (int i = 9; i >= 0; --i)
            {
                // i. - iv.
                BigInteger y = CalculateY_FF1(cipher, bigRadix, T, b, d, i, P, A);

                // v.
                m = n - m;
                BigInteger modulus = modUV[i & 1];

                // vi.
                BigInteger c = Num(bigRadix, B).Subtract(y).Mod(modulus);

                // vii. - ix.
                ushort[] C = B;
                B = A;
                A = C;
                Str(bigRadix, c, m, C, 0);
            }

            return Arrays.Concatenate(A, B);
        }

        public static byte[] DecryptFF3(IBlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len)
        {
            CheckArgs(cipher, false, radix, buf, off, len);

            if (tweak64.Length != 8)
                throw new ArgumentException();

            return ImplDecryptFF3(cipher, radix, tweak64, buf, off, len);
        }

        public static byte[] DecryptFF3_1(IBlockCipher cipher, int radix, byte[] tweak56, byte[] buf, int off, int len)
        {
            CheckArgs(cipher, false, radix, buf, off, len);

            if (tweak56.Length != 7)
                throw new ArgumentException("tweak should be 56 bits");

            byte[] tweak64 = CalculateTweak64_FF3_1(tweak56);

            return ImplDecryptFF3(cipher, radix, tweak64, buf, off, len);
        }

        public static ushort[] DecryptFF3_1w(IBlockCipher cipher, int radix, byte[] tweak56, ushort[] buf, int off, int len)
        {
            CheckArgs(cipher, false, radix, buf, off, len);

            if (tweak56.Length != 7)
                throw new ArgumentException("tweak should be 56 bits");

            byte[] tweak64 = CalculateTweak64_FF3_1(tweak56);

            return ImplDecryptFF3w(cipher, radix, tweak64, buf, off, len);
        }

        public static byte[] EncryptFF1(IBlockCipher cipher, int radix, byte[] tweak, byte[] buf, int off, int len)
        {
            CheckArgs(cipher, true, radix, buf, off, len);

            // Algorithm 7
            int n = len;
            int u = n / 2, v = n - u;

            ushort[] A = ToShort(buf, off, u);
            ushort[] B = ToShort(buf, off + u, v);

            return ToByte(EncFF1(cipher, radix, tweak, n, u, v, A, B));
        }

        public static ushort[] EncryptFF1w(IBlockCipher cipher, int radix, byte[] tweak, ushort[] buf, int off, int len)
        {
            CheckArgs(cipher, true, radix, buf, off, len);

            // Algorithm 7
            int n = len;
            int u = n / 2, v = n - u;

            ushort[] A = new ushort[u];
            ushort[] B = new ushort[v];

            Array.Copy(buf, off, A, 0, u);
            Array.Copy(buf, off + u, B, 0, v);

            return EncFF1(cipher, radix, tweak, n, u, v, A, B);
        }

        private static ushort[] EncFF1(IBlockCipher cipher, int radix, byte[] T, int n, int u, int v, ushort[] A, ushort[] B)
        {
            int t = T.Length;

            int b = CalculateB_FF1(radix, v);
            int d = (b + 7) & ~3;

            byte[] P = CalculateP_FF1(radix, (byte)u, n, t);

            BigInteger bigRadix = BigInteger.ValueOf(radix);
            BigInteger[] modUV = CalculateModUV(bigRadix, u, v);

            int m = v;

            for (int i = 0; i < 10; ++i)
            {
                // i. - iv.
                BigInteger y = CalculateY_FF1(cipher, bigRadix, T, b, d, i, P, B);

                // v.
                m = n - m;
                BigInteger modulus = modUV[i & 1];

                // vi.
                BigInteger c = Num(bigRadix, A).Add(y).Mod(modulus);

                // vii. - ix.
                ushort[] C = A;
                A = B;
                B = C;
                Str(bigRadix, c, m, C, 0);
            }

            return Arrays.Concatenate(A, B);
        }

        public static byte[] EncryptFF3(IBlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len)
        {
            CheckArgs(cipher, false, radix, buf, off, len);

            if (tweak64.Length != 8)
                throw new ArgumentException();

            return ImplEncryptFF3(cipher, radix, tweak64, buf, off, len);
        }

        public static ushort[] EncryptFF3w(IBlockCipher cipher, int radix, byte[] tweak64, ushort[] buf, int off, int len)
        {
            CheckArgs(cipher, false, radix, buf, off, len);

            if (tweak64.Length != 8)
                throw new ArgumentException();

            return ImplEncryptFF3w(cipher, radix, tweak64, buf, off, len);
        }

        public static ushort[] EncryptFF3_1w(IBlockCipher cipher, int radix, byte[] tweak56, ushort[] buf, int off, int len)
        {
            CheckArgs(cipher, false, radix, buf, off, len);

            if (tweak56.Length != 7)
                throw new ArgumentException("tweak should be 56 bits");

            byte[] tweak64 = CalculateTweak64_FF3_1(tweak56);

            return EncryptFF3w(cipher, radix, tweak64, buf, off, len);
        }

        public static byte[] EncryptFF3_1(IBlockCipher cipher, int radix, byte[] tweak56, byte[] buf, int off, int len)
        {
            CheckArgs(cipher, false, radix, buf, off, len);

            if (tweak56.Length != 7)
                throw new ArgumentException("tweak should be 56 bits");

            byte[] tweak64 = CalculateTweak64_FF3_1(tweak56);

            return EncryptFF3(cipher, radix, tweak64, buf, off, len);
        }

        private static int CalculateB_FF1(int radix, int v)
        {
            //return (BigInteger.ValueOf(radix).Pow(v).Subtract(BigInteger.One).BitLength + 7) / 8;

            int powersOfTwo = Integers.NumberOfTrailingZeros(radix);
            int bits = powersOfTwo * v;

            int oddPart = radix >> powersOfTwo;
            if (oddPart != 1)
            {
                // Old version with rounding issues, especially for power of 2 radix, but maybe others.
                //bits += (int)System.Math.Ceiling(System.Math.Log((double)oddPart) * (double)v / LOG2);

                // Exact calculation, with possible performance issues if v is too large.
                bits += BigInteger.ValueOf(oddPart).Pow(v).BitLength;
            }

            return (bits + 7) / 8;
        }

        private static BigInteger[] CalculateModUV(BigInteger bigRadix, int u, int v)
        {
            BigInteger[] modUV = new BigInteger[2];
            modUV[0] = bigRadix.Pow(u);
            modUV[1] = modUV[0];
            if (v != u)
            {
                modUV[1] = modUV[1].Multiply(bigRadix);
            }
            return modUV;
        }

        private static byte[] CalculateP_FF1(int radix, byte uLow, int n, int t)
        {
            byte[] P = new byte[BLOCK_SIZE];
            P[0] = 1;
            P[1] = 2;
            P[2] = 1;

            // Radix
            P[3] = 0;
            P[4] = (byte)(radix >> 8);
            P[5] = (byte)radix;

            P[6] = 10;
            P[7] = uLow;
            Pack.UInt32_To_BE((uint)n, P, 8);
            Pack.UInt32_To_BE((uint)t, P, 12);
            return P;
        }

        private static byte[] CalculateTweak64_FF3_1(byte[] tweak56)
        {
            byte[] tweak64 = new byte[8];
            tweak64[0] = tweak56[0];
            tweak64[1] = tweak56[1];
            tweak64[2] = tweak56[2];
            tweak64[3] = (byte)(tweak56[3] & 0xF0);
            tweak64[4] = tweak56[4];
            tweak64[5] = tweak56[5];
            tweak64[6] = tweak56[6];
            tweak64[7] = (byte)(tweak56[3] << 4);

            return tweak64;
        }

        private static BigInteger CalculateY_FF1(IBlockCipher cipher, BigInteger bigRadix, byte[] T, int b, int d,
            int round, byte[] P, ushort[] AB)
        {
            int t = T.Length;

            // i.
            int zeroes = -(t + b + 1) & 15;
            byte[] Q = new byte[t + zeroes + 1 + b];
            Array.Copy(T, 0, Q, 0, t);
            Q[t + zeroes] = (byte)round;

            BigInteger numAB = Num(bigRadix, AB);
            BigIntegers.AsUnsignedByteArray(numAB, Q, Q.Length - b, b);

            // ii.
            byte[] R = Prf(cipher, Arrays.Concatenate(P, Q));

            // iii.
            byte[] sBlocks = R;
            if (d > BLOCK_SIZE)
            {
                int sBlocksLen = (d + BLOCK_SIZE - 1) / BLOCK_SIZE;
                sBlocks = new byte[sBlocksLen * BLOCK_SIZE];

                uint j0 = Pack.BE_To_UInt32(R, BLOCK_SIZE - 4);
                Array.Copy(R, 0, sBlocks, 0, BLOCK_SIZE);

                for (uint j = 1; j < sBlocksLen; ++j)
                {
                    int sOff = (int)(j * BLOCK_SIZE);

                    Array.Copy(R, 0, sBlocks, sOff, BLOCK_SIZE - 4);
                    Pack.UInt32_To_BE(j0 ^ j, sBlocks, sOff + BLOCK_SIZE - 4);

                    cipher.ProcessBlock(sBlocks, sOff, sBlocks, sOff);
                }
            }

            // iv.
            return new BigInteger(1, sBlocks, 0, d);
        }

        private static BigInteger CalculateY_FF3(IBlockCipher cipher, BigInteger bigRadix, byte[] T, int wOff,
            uint round, ushort[] AB)
        {
            // ii.
            byte[] P = new byte[BLOCK_SIZE];
            Pack.UInt32_To_BE(Pack.BE_To_UInt32(T, wOff) ^ round, P, 0);

            BigInteger numAB = Num(bigRadix, AB);
            BigIntegers.AsUnsignedByteArray(numAB, P, 4, BLOCK_SIZE - 4);

            // iii.
            Array.Reverse(P);
            cipher.ProcessBlock(P, 0, P, 0);
            byte[] S = P;

            // iv.
            return new BigInteger(1, S, bigEndian: false);
        }

        private static void CheckArgs(IBlockCipher cipher, bool isFF1, int radix, ushort[] buf, int off, int len)
        {
            CheckCipher(cipher);
            if (radix < 2 || radix > (1 << 16))
                throw new ArgumentException();

            CheckData(isFF1, radix, buf, off, len);
        }

        private static void CheckArgs(IBlockCipher cipher, bool isFF1, int radix, byte[] buf, int off, int len)
        {
            CheckCipher(cipher);
            if (radix < 2 || radix > (1 << 8))
                throw new ArgumentException();

            CheckData(isFF1, radix, buf, off, len);
        }

        private static void CheckCipher(IBlockCipher cipher)
        {
            if (BLOCK_SIZE != cipher.GetBlockSize())
                throw new ArgumentException();
        }

        private static void CheckData(bool isFF1, int radix, ushort[] buf, int off, int len)
        {
            CheckLength(isFF1, radix, len);
            for (int i = 0; i < len; ++i)
            {
                int b = buf[off + i] & 0xFFFF;
                if (b >= radix)
                    throw new ArgumentException("input data outside of radix");
            }
        }

        private static void CheckData(bool isFF1, int radix, byte[] buf, int off, int len)
        {
            CheckLength(isFF1, radix, len);
            for (int i = 0; i < len; ++i)
            {
                int b = buf[off + i] & 0xFF;
                if (b >= radix)
                    throw new ArgumentException("input data outside of radix");
            }
        }

        private static void CheckLength(bool isFF1, int radix, int len)
        {
            if (len < 2 || System.Math.Pow(radix, len) < 1000000)
                throw new ArgumentException("input too short");

            if (!isFF1)
            {
                int maxLen = 2 * (int)(System.Math.Floor(System.Math.Log(TWO_TO_96) / System.Math.Log(radix)));
                if (len > maxLen)
                    throw new ArgumentException("maximum input length is " + maxLen);
            }
        }

        private static byte[] ImplDecryptFF3(IBlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len)
        {
            // Algorithm 10
            byte[] T = tweak64;
            int n = len;
            int v = n / 2, u = n - v;

            ushort[] A = ToShort(buf, off, u);
            ushort[] B = ToShort(buf, off + u, v);

            ushort[] rv = DecFF3_1(cipher, radix, T, n, v, u, A, B);

            return ToByte(rv);
        }

        private static ushort[] ImplDecryptFF3w(IBlockCipher cipher, int radix, byte[] tweak64, ushort[] buf, int off, int len)
        {
            // Algorithm 10
            byte[] T = tweak64;
            int n = len;
            int v = n / 2, u = n - v;

            ushort[] A = new ushort[u];
            ushort[] B = new ushort[v];

            Array.Copy(buf, off, A, 0, u);
            Array.Copy(buf, off + u, B, 0, v);

            return DecFF3_1(cipher, radix, T, n, v, u, A, B);
        }

        private static ushort[] DecFF3_1(IBlockCipher cipher, int radix, byte[] T, int n, int v, int u, ushort[] A, ushort[] B)
        {
            BigInteger bigRadix = BigInteger.ValueOf(radix);
            BigInteger[] modVU = CalculateModUV(bigRadix, v, u);

            int m = u;

            // Note we keep A, B in reverse order throughout
            Array.Reverse(A);
            Array.Reverse(B);

            for (int i = 7; i >= 0; --i)
            {
                // i.
                m = n - m;
                BigInteger modulus = modVU[1 - (i & 1)];
                int wOff = 4 - ((i & 1) * 4);

                // ii. - iv.
                BigInteger y = CalculateY_FF3(cipher, bigRadix, T, wOff, (uint)i, A);

                // v.
                BigInteger c = Num(bigRadix, B).Subtract(y).Mod(modulus);

                // vi. - viii.
                ushort[] C = B;
                B = A;
                A = C;
                Str(bigRadix, c, m, C, 0);
            }

            Array.Reverse(A);
            Array.Reverse(B);

            return Arrays.Concatenate(A, B);
        }

        private static byte[] ImplEncryptFF3(IBlockCipher cipher, int radix, byte[] tweak64, byte[] buf, int off, int len)
        {
            // Algorithm 9
            byte[] T = tweak64;
            int n = len;
            int v = n / 2, u = n - v;

            ushort[] A = ToShort(buf, off, u);
            ushort[] B = ToShort(buf, off + u, v);

            ushort[] rv = EncFF3_1(cipher, radix, T, n, v, u, A, B);

            return ToByte(rv);
        }

        private static ushort[] ImplEncryptFF3w(IBlockCipher cipher, int radix, byte[] tweak64, ushort[] buf, int off, int len)
        {
            // Algorithm 9
            byte[] T = tweak64;
            int n = len;
            int v = n / 2, u = n - v;

            ushort[] A = new ushort[u];
            ushort[] B = new ushort[v];

            Array.Copy(buf, off, A, 0, u);
            Array.Copy(buf, off + u, B, 0, v);

            return EncFF3_1(cipher, radix, T, n, v, u, A, B);
        }

        private static ushort[] EncFF3_1(IBlockCipher cipher, int radix, byte[] t, int n, int v, int u, ushort[] a, ushort[] b)
        {
            BigInteger bigRadix = BigInteger.ValueOf(radix);
            BigInteger[] modVU = CalculateModUV(bigRadix, v, u);

            int m = v;

            // Note we keep A, B in reverse order throughout
            Array.Reverse(a);
            Array.Reverse(b);

            for (uint i = 0; i < 8; ++i)
            {
                // i.
                m = n - m;
                BigInteger modulus = modVU[1 - (i & 1)];
                int wOff = 4 - (int)((i & 1) * 4);

                // ii. - iv.
                BigInteger y = CalculateY_FF3(cipher, bigRadix, t, wOff, i, b);

                // v.
                BigInteger c = Num(bigRadix, a).Add(y).Mod(modulus);

                // vi. - viii.
                ushort[] C = a;
                a = b;
                b = C;
                Str(bigRadix, c, m, C, 0);
            }

            Array.Reverse(a);
            Array.Reverse(b);

            return Arrays.Concatenate(a, b);
        }

        private static BigInteger Num(BigInteger R, ushort[] x)
        {
            BigInteger result = BigInteger.Zero;
            for (int i = 0; i < x.Length; ++i)
            {
                result = result.Multiply(R).Add(BigInteger.ValueOf(x[i] & 0xFFFF));
            }
            return result;
        }

        private static byte[] Prf(IBlockCipher c, byte[] x)
        {
            if ((x.Length % BLOCK_SIZE) != 0)
                throw new ArgumentException();

            int m = x.Length / BLOCK_SIZE;
            byte[] y = new byte[BLOCK_SIZE];

            for (int i = 0; i < m; ++i)
            {
                Bytes.XorTo(BLOCK_SIZE, x, i * BLOCK_SIZE, y, 0);
                c.ProcessBlock(y, 0, y, 0);
            }

            return y;
        }

        private static void Str(BigInteger R, BigInteger x, int m, ushort[] output, int off)
        {
            if (x.SignValue < 0)
                throw new ArgumentException();

            for (int i = 1; i <= m; ++i)
            {
                BigInteger[] qr = x.DivideAndRemainder(R);
                output[off + m - i] = (ushort)qr[1].IntValue;
                x = qr[0];
            }
            if (x.SignValue != 0)
                throw new ArgumentException();
        }

        private static byte[] ToByte(ushort[] buf)
        {
            byte[] s = new byte[buf.Length];

            for (int i = 0; i != s.Length; i++)
            {
                s[i] = (byte)buf[i];
            }

            return s;
        }

        private static ushort[] ToShort(byte[] buf, int off, int len)
        {
            ushort[] s = new ushort[len];

            for (int i = 0; i != s.Length; i++)
            {
                s[i] = (ushort)(buf[off + i] & 0xFF);
            }

            return s;
        }
    }
}
