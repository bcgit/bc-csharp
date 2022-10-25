using System;
using System.Diagnostics;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal sealed class BikeRing
    {
        private readonly int m_bits;
        private readonly int m_size;
        private readonly int m_sizeExt;

        internal BikeRing(int r)
        {
            if ((r & 0x80000001) != 1)
                throw new ArgumentException();

            m_bits = r;
            m_size = (r + 63) >> 6;
            m_sizeExt = m_size * 2;
        }

        internal void Add(ulong[] x, ulong[] y, ulong[] z)
        {
            Nat.Xor64(Size, x, y, z);
        }

        internal void AddTo(ulong[] x, ulong[] z)
        {
            Nat.XorTo64(Size, x, z);
        }

        internal void Copy(ulong[] x, ulong[] z)
        {
            for (int i = 0; i < Size; ++i)
            {
                z[i] = x[i];
            }
        }

        internal ulong[] Create()
        {
            return new ulong[Size];
        }

        internal ulong[] CreateExt()
        {
            return new ulong[SizeExt];
        }

        internal ulong[] DecodeBits(byte[] bs)
        {
            if (bs.Length > m_bits)
                throw new ArgumentException();

            ulong[] z = Create();
            for (int i = 0; i < bs.Length; ++i)
            {
                ulong bit = bs[i];
                if ((bit >> 1) != 0UL)
                    throw new ArgumentException();

                z[i >> 6] |= bit << (i & 63);
            }
            return z;
        }

        internal void DecodeBytes(byte[] bs, ulong[] z)
        {
            int partialBits = m_bits & 63;
            Pack.LE_To_UInt64(bs, 0, z, 0, Size - 1);
            byte[] last = new byte[8];
            Array.Copy(bs, (Size - 1) << 3, last, 0, (partialBits + 7) >> 3);
            z[Size - 1] = Pack.LE_To_UInt64(last);
            Debug.Assert((z[Size - 1] >> partialBits) == 0);
        }

        internal byte[] EncodeBits(ulong[] x)
        {
            byte[] bs = new byte[m_bits];
            for (int i = 0; i < m_bits; ++i)
            {
                bs[i] = (byte)((x[i >> 6] >> (i & 63)) & 1UL);
            }
            return bs;
        }

        internal void EncodeBytes(ulong[] x, byte[] bs)
        {
            int partialBits = m_bits & 63;
            Debug.Assert((x[Size - 1] >> partialBits) == 0);
            Pack.UInt64_To_LE(x, 0, Size - 1, bs, 0);
            byte[] last = new byte[8];
            Pack.UInt64_To_LE(x[Size - 1], last);
            Array.Copy(last, 0, bs, (Size - 1) << 3, (partialBits + 7) >> 3);
        }

        internal ulong[] GenerateRandom(int weight, IXof digest)
        {
            byte[] buf = new byte[4];
            int highest = Integers.HighestOneBit(m_bits);
            int mask = highest | (highest - 1);

            ulong[] z = Create();
            int count = 0;
            while (count < weight)
            {
                digest.Output(buf, 0, 4);
                int candidate = (int)Pack.LE_To_UInt32(buf) & mask;
                if (candidate < m_bits)
                {
                    int pos = candidate >> 6;
                    ulong bit = 1UL << (candidate & 63);
                    if ((z[pos] & bit) == 0UL)
                    {
                        z[pos] |= bit;
                        ++count;
                    }
                }
            }
            return z;
        }

        internal void Inv(ulong[] a, ulong[] z)
        {
            ulong[] f = Create();
            ulong[] g = Create();
            ulong[] t = Create();

            Copy(a, f);
            Copy(a, t);

            int rSub2 = m_bits - 2;
            int bits = 32 - Integers.NumberOfLeadingZeros(rSub2);

            for (int i = 1; i < bits; ++i)
            {
                SquareN(f, 1 << (i - 1), g);
                Multiply(f, g, f);

                if ((rSub2 & (1 << i)) != 0)
                {
                    int n = rSub2 & ((1 << i) - 1);
                    SquareN(f, n, g);
                    Multiply(t, g, t);
                }
            }

            Square(t, z);
        }

        internal void Multiply(ulong[] x, ulong[] y, ulong[] z)
        {
            ulong[] tt = CreateExt();
            ImplMultiplyAcc(x, y, tt);
            Reduce(tt, z);
        }

        internal void Reduce(ulong[] tt, ulong[] z)
        {
            int partialBits = m_bits & 63;
            int excessBits = 64 - partialBits;
            ulong partialMask = ulong.MaxValue >> excessBits;

            ulong c = Nat.ShiftUpBits64(Size, tt, Size, excessBits, tt[Size - 1], z, 0);
            Debug.Assert(c == 0UL);
            AddTo(tt, z);
            z[Size - 1] &= partialMask;
        }

        internal int Size => m_size;

        internal int SizeExt => m_sizeExt;

        internal void Square(ulong[] x, ulong[] z)
        {
            ulong[] tt = CreateExt();
            ImplSquare(x, tt);
            Reduce(tt, z);
        }

        internal void SquareN(ulong[] x, int n, ulong[] z)
        {
            Debug.Assert(n > 0);

            ulong[] tt = CreateExt();
            ImplSquare(x, tt);
            Reduce(tt, z);

            while (--n > 0)
            {
                ImplSquare(z, tt);
                Reduce(tt, z);
            }
        }

        private void ImplMultiplyAcc(ulong[] x, ulong[] y, ulong[] zz)
        {
            ulong[] u = new ulong[16];

            // Schoolbook

            //for (int i = 0; i < Size; ++i)
            //{
            //    ulong x_i = x[i];

            //    for (int j = 0; j < Size; ++j)
            //    {
            //        ulong y_j = y[j];

            //        ImplMulwAcc(u, x_i, y_j, zz, i + j);
            //    }
            //}

            // Arbitrary-degree Karatsuba

            for (int i = 0; i < Size; ++i)
            {
                ImplMulwAcc(u, x[i], y[i], zz, i << 1);
            }

            ulong v0 = zz[0], v1 = zz[1];
            for (int i = 1; i < Size; ++i)
            {
                v0 ^= zz[i << 1]; zz[i] = v0 ^ v1; v1 ^= zz[(i << 1) + 1];
            }

            ulong w = v0 ^ v1;
            for (int i = 0; i < Size; ++i)
            {
                zz[Size + i] = zz[i] ^ w;
            }

            int last = Size - 1;
            for (int zPos = 1; zPos < (last * 2); ++zPos)
            {
                int hi = System.Math.Min(last, zPos);
                int lo = zPos - hi;

                while (lo < hi)
                {
                    ImplMulwAcc(u, x[lo] ^ x[hi], y[lo] ^ y[hi], zz, zPos);

                    ++lo;
                    --hi;
                }
            }
        }

        private static void ImplMulwAcc(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Pclmulqdq.IsSupported)
            {
                var X = Vector128.CreateScalar(x);
                var Y = Vector128.CreateScalar(y);
                var Z = Pclmulqdq.CarrylessMultiply(X, Y, 0x00);
                z[zOff    ] ^= Z.GetElement(0);
                z[zOff + 1] ^= Z.GetElement(1);
                return;
            }
#endif

            //u[0] = 0;
            u[1] = y;
            for (int i = 2; i < 16; i += 2)
            {
                u[i    ] = u[i >> 1] << 1;
                u[i + 1] = u[i     ] ^  y;
            }

            uint j = (uint)x;
            ulong g, h = 0, l = u[j & 15]
                              ^ u[(j >> 4) & 15] << 4;
            int k = 56;
            do
            {
                j  = (uint)(x >> k);
                g  = u[j & 15]
                   ^ u[(j >> 4) & 15] << 4;
                l ^= (g << k);
                h ^= (g >> -k);
            }
            while ((k -= 8) > 0);

            for (int p = 0; p < 7; ++p)
            {
                x = (x & 0xFEFEFEFEFEFEFEFEUL) >> 1;
                h ^= x & (ulong)((long)(y << p) >> 63);
            }

            Debug.Assert(h >> 63 == 0);

            z[zOff    ] ^= l;
            z[zOff + 1] ^= h;
        }

        private void ImplSquare(ulong[] x, ulong[] zz)
        {
            Interleave.Expand64To128(x, 0, Size, zz, 0);
        }
    }
}
