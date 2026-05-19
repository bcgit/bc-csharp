using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math.BinPoly;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    internal sealed class GF2x
    {
        private readonly IBinPolyMul m_binPolyMul;
        private readonly int m_bits;
        private readonly int m_size;

        internal GF2x(int n)
        {
            if ((n & 0xFFFF0001) != 1)
                throw new ArgumentException();

            m_binPolyMul = BinPolys.Mul.Binomial(n);
            m_bits = n;
            m_size = BinPolys.Size(n);
        }

        internal void AddTo(ulong[] x, ulong[] z) => BinPolys.AddTo(m_size, x, 0, z, 0);

        internal void Clear(ulong[] z) => BinPolys.Clear(m_size, z, 0);

        internal ulong[] Create() => BinPolys.Create(m_size);

        internal ulong EqualTo(ulong[] x, ulong[] y) => BinPolys.EqualTo(m_size, x, 0, y, 0);

        internal void Mul(ulong[] x, ulong[] y, ulong[] z) => m_binPolyMul.Multiply(x, 0, y, 0, z, 0);

        internal void Random(Shake256RandomGenerator generator, ulong[] z)
        {
            byte[] tmp = new byte[m_size << 3];
            generator.XofGetBytes(tmp, Utils.GetByteSizeFromBitSize(m_bits));
            Pack.LE_To_UInt64(tmp, 0, z);
            z[m_size - 1] &= (1UL << (m_bits & 63)) - 1UL;
        }
    }
}
