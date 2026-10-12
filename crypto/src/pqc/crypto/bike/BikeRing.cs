using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.BinPoly;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    internal sealed class BikeRing
    {
        private readonly IBinPolyMul m_binPolyMul;
        private readonly int m_bits;
        private readonly int m_size;

        internal BikeRing(int r)
        {
            if ((r & 0xFFFF0001) != 1)
                throw new ArgumentException();

            m_binPolyMul = BinPolys.Mul.Binomial(r);
            m_bits = r;
            m_size = BinPolys.Size(r);
        }

        internal void Add(ulong[] x, ulong[] y, ulong[] z) => BinPolys.Add(m_size, x, 0, y, 0, z, 0);

        internal void AddTo(ulong[] x, ulong[] z) => BinPolys.AddTo(m_size, x, 0, z, 0);

        internal void Copy(ulong[] x, ulong[] z) => BinPolys.Copy(m_size, x, 0, z, 0);

        internal ulong[] Create() => BinPolys.Create(m_size);

        internal void DecodeBytes(byte[] bs, ulong[] z)
        {
            int last = Size - 1;
            int partialBits = m_bits & 63;
            int partialBytes = (partialBits + 7) >> 3;
            Pack.LE_To_UInt64(bs, 0, z, 0, last);
            z[last] = Pack.LE_To_UInt64_Low(bs, last << 3, partialBytes);
            Debug.Assert((z[last] >> partialBits) == 0UL);
        }

        internal byte[] EncodeBitsTransposed(ulong[] x)
        {
            byte[] bs = new byte[m_bits];
            bs[0] = (byte)(x[0] & 1UL);
            for (int i = 1; i < m_bits; ++i)
            {
                bs[m_bits - i] = (byte)((x[i >> 6] >> (i & 63)) & 1UL);
            }
            return bs;
        }

        internal void EncodeBytes(ulong[] x, byte[] bs)
        {
            int last = Size - 1;
            int partialBits = m_bits & 63;
            int partialBytes = (partialBits + 7) >> 3;
            Debug.Assert((x[last] >> partialBits) == 0UL);
            Pack.UInt64_To_LE(x, 0, last, bs, 0);
            Pack.UInt64_To_LE_Low(x[last], bs, last << 3, partialBytes);
        }

        internal void Inv(ulong[] a, ulong[] z)
        {
            /*
             * Algorithm for inversion is based on https://ia.cr/2020/298 (Nir Drucker, Shay Gueron, Dusan Kostic,
             * "Fast polynomial inversion for post quantum QC-MDPC cryptography"), in particular replacing large
             * squarings with permutations. The binomial IBinPolyMul applies that substitution inside SquareN, deriving
             * the permutation from 2^-n mod r on the fly rather than from precomputed tables.
             */

            ulong[] f = Create();
            ulong[] g = Create();
            ulong[] t = Create();

            Copy(a, f);
            Copy(a, t);

            int rSub2 = m_bits - 2;
            int bits = Integers.BitLength(rSub2);

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

        internal void Multiply(ulong[] x, ulong[] y, ulong[] z) => Multiply(x, 0, y, 0, z);

        internal void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z) =>
            m_binPolyMul.Multiply(x, xOff, y, yOff, z, 0);

        internal int Size => m_size;

        internal void Square(ulong[] x, ulong[] z) => m_binPolyMul.Square(x, 0, z, 0);

        internal void SquareN(ulong[] x, int n, ulong[] z) => m_binPolyMul.SquareN(x, 0, n, z, 0);
    }
}
