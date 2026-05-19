#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.BinPoly.X86.V128
{
    internal sealed class Size10
        : BinPolyMulBase
    {
        private const int FixedSize = 10;
        private const int FixedSizeExt = 2 * FixedSize;

        internal Size10(int n, IReduce reduce)
            : base(n, reduce)
        {
            Debug.Assert(m_size == FixedSize && m_sizeExt == FixedSizeExt);
        }

        public override void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            Span<ulong> tt = stackalloc ulong[FixedSizeExt];
            Kernels.ImplMul10(x.AsSpan(xOff, FixedSize), y.AsSpan(yOff, FixedSize), tt);
            m_reduce.Reduce(tt, z.AsSpan(zOff, FixedSize));
            BinPolys.Clear(FixedSizeExt, tt);
        }
    }
}
#endif
