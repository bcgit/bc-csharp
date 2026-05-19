#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.BinPoly.X86.V128
{
    /// <summary>
    /// Sealed <see cref="IBinPolyMul"/> impl for the odd-sized half of the mid-band:
    /// dispatched for odd <c>m_size</c> values in
    /// <c>[11, Large.KaratsubaCutoff)</c>. Counterpart to <see cref="MediumEven"/>,
    /// which handles even <c>m_size</c> in the same range.
    /// </summary>
    /// <remarks>
    /// Multiply is a single stackalloc tt + <see cref="Kernels.ImplMulOdd"/> + reduce
    /// -- same shape as <see cref="MediumEven"/>. The kernel reads the tail ulong
    /// directly from the operand span and synthesises a half-V128 limb in registers,
    /// so no secret-bearing padded copies of x / y exist (and nothing to wipe).
    /// </remarks>
    internal sealed class MediumOdd
        : BinPolyMulBase
    {
        internal MediumOdd(int n, IReduce reduce)
            : base(n, reduce)
        {
            Debug.Assert((m_size & 1) == 1 && m_size >= 11 && m_size < Large.KaratsubaCutoff);
            Debug.Assert(m_sizeExt <= StackAllocCutoff);
        }

        public override void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            Span<ulong> tt = stackalloc ulong[m_sizeExt];
            Kernels.ImplMulOdd(x.AsSpan(xOff, m_size), y.AsSpan(yOff, m_size), tt);
            m_reduce.Reduce(tt, z.AsSpan(zOff, m_size));
            BinPolys.Clear(m_sizeExt, tt);
        }
    }
}
#endif
