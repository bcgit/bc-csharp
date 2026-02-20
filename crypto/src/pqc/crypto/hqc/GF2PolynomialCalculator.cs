using System;
using System.Diagnostics;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal class GF2PolynomialCalculator
    {
#if NETCOREAPP3_0_OR_GREATER
        private static bool IsHardwareAccelerated => false;// Org.BouncyCastle.Runtime.Intrinsics.X86.Pclmulqdq.IsEnabled;
#endif

        private readonly int m_bits;
        private readonly int m_size;
        private readonly int m_sizeExt;

        internal GF2PolynomialCalculator(int n)
        {
            if ((n & 0xFFFF0001) != 1)
                throw new ArgumentException();

            m_bits = n;
            m_size = Utils.GetByte64SizeFromBitSize(n);
            m_sizeExt = m_size * 2;
        }

        internal void AddTo(ulong[] x, ulong[] z) => Nat.XorTo64(m_size, x, z);

        internal ulong[] Create() => new ulong[m_size];

        internal ulong[] CreateExt() => new ulong[m_sizeExt];

        internal ulong EqualTo(ulong[] x, ulong[] y) => Nat.EqualTo64(m_size, x, y);

        internal void Mul(ulong[] x, ulong[] y, ulong[] z)
        {
            ulong[] tt = CreateExt();
            ulong[] tmp = new ulong[m_size << 4];
            Karatsuba(m_size, x, 0, y, 0, tt, 0, tmp, 0);
            Reduce(tt, z);
        }

        private static void BaseMul(int len, ulong[] x, int xOff, ulong[] y, int yOff, ulong[] zz, int zzOff)
        {
            int lenExt = len * 2;
            Arrays.Fill(zz, zzOff, zzOff + lenExt, 0UL);

#if NETCOREAPP3_0_OR_GREATER
            if (IsHardwareAccelerated)
            {
                var xBounds = x[xOff + len - 1];
                var yBounds = y[yOff + len - 1];
                var zzBounds = zz[zzOff + lenExt - 1];

                int i = 0;

                int limit4 = len - 4;
                while (i <= limit4)
                {
                    var X01 = Vector128.Create(x[xOff + i + 0], x[xOff + i + 1]);
                    var X23 = Vector128.Create(x[xOff + i + 2], x[xOff + i + 3]);

                    int j = 0;
                    while (j <= limit4)
                    {
                        var Y01 = Vector128.Create(y[yOff + j + 0], y[yOff + j + 1]);
                        var Y23 = Vector128.Create(y[yOff + j + 2], y[yOff + j + 3]);

                        var Z01 = Pclmulqdq.CarrylessMultiply(X01, Y01, 0x00);
                        var Z12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y01, 0x01),
                                           Pclmulqdq.CarrylessMultiply(X01, Y01, 0x10));
                        var Z23 = Pclmulqdq.CarrylessMultiply(X01, Y01, 0x11);

                        var T23 = Pclmulqdq.CarrylessMultiply(X01, Y23, 0x00);
                        var T34 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X01, Y23, 0x01),
                                           Pclmulqdq.CarrylessMultiply(X01, Y23, 0x10));
                        var T45 = Pclmulqdq.CarrylessMultiply(X01, Y23, 0x11);

                        var U23 = Pclmulqdq.CarrylessMultiply(X23, Y01, 0x00);
                        var U34 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X23, Y01, 0x01),
                                           Pclmulqdq.CarrylessMultiply(X23, Y01, 0x10));
                        var U45 = Pclmulqdq.CarrylessMultiply(X23, Y01, 0x11);

                        var Z45 = Pclmulqdq.CarrylessMultiply(X23, Y23, 0x00);
                        var Z56 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(X23, Y23, 0x01),
                                           Pclmulqdq.CarrylessMultiply(X23, Y23, 0x10));
                        var Z67 = Pclmulqdq.CarrylessMultiply(X23, Y23, 0x11);

                        Z23 = Sse2.Xor(Z23, T23);
                        Z23 = Sse2.Xor(Z23, U23);
                        var Z34 = Sse2.Xor(T34, U34);
                        Z45 = Sse2.Xor(Z45, T45);
                        Z45 = Sse2.Xor(Z45, U45);

                        Z01 = Sse2.Xor(Z01, Sse2.ShiftLeftLogical128BitLane (Z12, 8));

                        if (Org.BouncyCastle.Runtime.Intrinsics.X86.Ssse3.IsEnabled)
                        {
                            Z23 = Sse2.Xor(Z23, Ssse3.AlignRight(Z34, Z12, 8));
                            Z45 = Sse2.Xor(Z45, Ssse3.AlignRight(Z56, Z34, 8));
                        }
                        else
                        {
                            Z23 = Sse2.Xor(Z23, Sse2.ShiftRightLogical128BitLane(Z12, 8));
                            Z23 = Sse2.Xor(Z23, Sse2.ShiftLeftLogical128BitLane (Z34, 8));
                            Z45 = Sse2.Xor(Z45, Sse2.ShiftRightLogical128BitLane(Z34, 8));
                            Z45 = Sse2.Xor(Z45, Sse2.ShiftLeftLogical128BitLane (Z56, 8));
                        }

                        Z67 = Sse2.Xor(Z67, Sse2.ShiftRightLogical128BitLane(Z56, 8));

                        zz[zzOff + i + j + 0] ^= Z01.GetElement(0);
                        zz[zzOff + i + j + 1] ^= Z01.GetElement(1);
                        zz[zzOff + i + j + 2] ^= Z23.GetElement(0);
                        zz[zzOff + i + j + 3] ^= Z23.GetElement(1);
                        zz[zzOff + i + j + 4] ^= Z45.GetElement(0);
                        zz[zzOff + i + j + 5] ^= Z45.GetElement(1);
                        zz[zzOff + i + j + 6] ^= Z67.GetElement(0);
                        zz[zzOff + i + j + 7] ^= Z67.GetElement(1);

                        j += 4;
                    }

                    i += 4;
                }

                int limit2 = len - 2;
                if (i <= limit2)
                {
                    var Xi = Vector128.Create(x[xOff + i], x[xOff + i + 1]);
                    var Yi = Vector128.Create(y[yOff + i], y[yOff + i + 1]);

                    for (int j = 0; j < i; j += 2)
                    {
                        var Xj = Vector128.Create(x[xOff + j], x[xOff + j + 1]);
                        var Yj = Vector128.Create(y[yOff + j], y[yOff + j + 1]);

                        var U01 = Pclmulqdq.CarrylessMultiply(Xi, Yj, 0x00);
                        var U12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(Xi, Yj, 0x01),
                                           Pclmulqdq.CarrylessMultiply(Xi, Yj, 0x10));
                        var U23 = Pclmulqdq.CarrylessMultiply(Xi, Yj, 0x11);

                        var V01 = Pclmulqdq.CarrylessMultiply(Xj, Yi, 0x00);
                        var V12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(Xj, Yi, 0x01),
                                           Pclmulqdq.CarrylessMultiply(Xj, Yi, 0x10));
                        var V23 = Pclmulqdq.CarrylessMultiply(Xj, Yi, 0x11);

                        var Z01 = Sse2.Xor(U01, V01);
                        var Z12 = Sse2.Xor(U12, V12);
                        var Z23 = Sse2.Xor(U23, V23);

                        Z01 = Sse2.Xor(Z01, Sse2.ShiftLeftLogical128BitLane (Z12, 8));
                        Z23 = Sse2.Xor(Z23, Sse2.ShiftRightLogical128BitLane(Z12, 8));

                        zz[zzOff + i + j + 0] ^= Z01.GetElement(0);
                        zz[zzOff + i + j + 1] ^= Z01.GetElement(1);
                        zz[zzOff + i + j + 2] ^= Z23.GetElement(0);
                        zz[zzOff + i + j + 3] ^= Z23.GetElement(1);
                    }

                    {
                        var Z01 = Pclmulqdq.CarrylessMultiply(Xi, Yi, 0x00);
                        var Z12 = Sse2.Xor(Pclmulqdq.CarrylessMultiply(Xi, Yi, 0x01),
                                           Pclmulqdq.CarrylessMultiply(Xi, Yi, 0x10));
                        var Z23 = Pclmulqdq.CarrylessMultiply(Xi, Yi, 0x11);

                        Z01 = Sse2.Xor(Z01, Sse2.ShiftLeftLogical128BitLane (Z12, 8));
                        Z23 = Sse2.Xor(Z23, Sse2.ShiftRightLogical128BitLane(Z12, 8));

                        zz[zzOff + i + i + 0] ^= Z01.GetElement(0);
                        zz[zzOff + i + i + 1] ^= Z01.GetElement(1);
                        zz[zzOff + i + i + 2] ^= Z23.GetElement(0);
                        zz[zzOff + i + i + 3] ^= Z23.GetElement(1);
                    }

                    i += 2;
                }

                if (i < len)
                {
                    var Xi = Vector128.CreateScalar(x[xOff + i]);
                    var Yi = Vector128.CreateScalar(y[yOff + i]);

                    for (int j = 0; j < i; ++j)
                    {
                        var Xj = Vector128.CreateScalar(x[xOff + j]);
                        var Yj = Vector128.CreateScalar(y[yOff + j]);

                        var Z = Sse2.Xor(Pclmulqdq.CarrylessMultiply(Xi, Yj, 0x00),
                                         Pclmulqdq.CarrylessMultiply(Yi, Xj, 0x00));

                        zz[zzOff + i + j + 0] ^= Z.GetElement(0);
                        zz[zzOff + i + j + 1] ^= Z.GetElement(1);
                    }

                    {
                        var Z = Pclmulqdq.CarrylessMultiply(Xi, Yi, 0x00);

                        zz[zzOff + i + i + 0] ^= Z.GetElement(0);
                        zz[zzOff + i + i + 1] ^= Z.GetElement(1);
                    }
                }
                return;
            }
#endif

            // Arbitrary-degree Karatsuba
            {
                ulong[] u = new ulong[16];

                for (int i = 0; i < len; ++i)
                {
                    ImplMulwAcc(u, x[xOff + i], y[yOff + i], zz, zzOff + (i << 1));
                }

                ulong v0 = zz[zzOff], v1 = zz[zzOff + 1];
                for (int i = 1; i < len; ++i)
                {
                    v0 ^= zz[zzOff + (i << 1)]; zz[zzOff + i] = v0 ^ v1; v1 ^= zz[zzOff + (i << 1) + 1];
                }

                ulong w = v0 ^ v1;
                Nat.Xor64(len, zz, zzOff, w, zz, zzOff + len);

                int last = len - 1;
                for (int zzPos = 1; zzPos < (last * 2); ++zzPos)
                {
                    int hi = System.Math.Min(last, zzPos);
                    int lo = zzPos - hi;

                    while (lo < hi)
                    {
                        ImplMulwAcc(u, x[xOff + lo] ^ x[xOff + hi], y[yOff + lo] ^ y[yOff + hi], zz, zzOff + zzPos);

                        ++lo;
                        --hi;
                    }
                }
            }
        }

        private void Karatsuba(int len, ulong[] x, int xOff, ulong[] y, int yOff, ulong[] zz, int zzOff, ulong[] tmp,
            int tmpOff)
        {
            int cutOff = 12;

#if NETCOREAPP3_0_OR_GREATER
            if (IsHardwareAccelerated)
            {
                cutOff = 24;
            }
#endif

            if (len < cutOff)
            {
                BaseMul(len, x, xOff, y, yOff, zz, zzOff);
                return;
            }

            // NB: This only works for n > 4
            Debug.Assert(len > 4);

            int m = len >> 1;
            int n1 = len - m;
            int sizeExt = len << 1;
            int mx2 = m << 1;
            int n1x2 = n1 << 1;

            int z2Offset = tmpOff + sizeExt;
            int zMidOffset = z2Offset + sizeExt;
            int taOffset = zMidOffset + sizeExt;
            int tbOffset = taOffset + len;
            int childBufferOffset = tmpOff + (len << 3);

            Karatsuba(m, x, xOff, y, yOff, tmp, tmpOff, tmp, childBufferOffset);
            Karatsuba(n1, x, xOff + m, y, yOff + m, tmp, z2Offset, tmp, childBufferOffset);

            for (int i = 0; i < n1; i++)
            {
                ulong loa = (i < m) ? x[xOff + i] : 0;
                ulong lob = (i < m) ? y[yOff + i] : 0;
                tmp[taOffset + i] = loa ^ x[xOff + m + i];
                tmp[tbOffset + i] = lob ^ y[yOff + m + i];
            }

            Karatsuba(n1, tmp, taOffset, tmp, tbOffset, tmp, zMidOffset, tmp, childBufferOffset);

            Array.Copy(tmp, tmpOff, zz, zzOff, mx2);
            Array.Copy(tmp, z2Offset, zz, zzOff + mx2, n1x2);

            for (int i = 0; i < 2 * n1; i++)
            {
                ulong z0i = (i < mx2) ? tmp[tmpOff + i] : 0;
                ulong z2i = (i < n1x2) ? tmp[z2Offset + i] : 0;
                zz[zzOff + m + i] ^= tmp[zMidOffset + i] ^ z0i ^ z2i;
            }
        }

        /**
         * Reduces a polynomial modulo {@code X^n - 1}.
         */
        private void Reduce(ulong[] tt, ulong[] z)
        {
            int partialBits = m_bits & 63;
            int excessBits = 64 - partialBits;
            ulong partialMask = ulong.MaxValue >> excessBits;

            ulong c = Nat.ShiftUpBits64(m_size, tt, m_size, excessBits, tt[m_size - 1], z, 0);
            Debug.Assert(c == 0UL);
            AddTo(tt, z);
            z[m_size - 1] &= partialMask;
        }

        /**
         * Carryless multiply of x and y, accumulating the result at z[zOff..zOff + 1], using u as a temporary buffer.
         */
        private static void ImplMulwAcc(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
        {
            ulong h = 0, m = x, n = y;

            //u[0] = 0UL;
            u[1] = y;
            for (int i = 2; i < 16; i += 2)
            {
                ulong u_i = u[i / 2] << 1;
                u[i    ] = u_i;
                u[i + 1] = u_i ^ y;

                // Interleave "repair" steps here for performance
                m = (m & 0xFEFEFEFEFEFEFEFEUL) >> 1;
                h ^= m & (ulong)((long)n >> 63);
                n <<= 1;
            }

            uint j = (uint)x;
            ulong g, l = u[j & 15]
                       ^ u[(j >> 4) & 15] << 4;
            int k = 56;
            do
            {
                j  = (uint)(x >> k);
                g  = u[j & 15]
                   ^ u[(j >> 4) & 15] << 4;
                l ^= g << k;
                h ^= g >> -k;
            }
            while ((k -= 8) > 0);

            Debug.Assert(h >> 63 == 0);

            z[zOff    ] ^= l;
            z[zOff + 1] ^= h;
        }
    }
}
