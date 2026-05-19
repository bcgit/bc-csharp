#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.BinPoly.X86.V128
{
    /// <summary>
    /// Sealed <see cref="IBinPolyMul"/> impl for the even-sized half of the mid-band:
    /// dispatched for even <c>m_size</c> values in
    /// <c>[12, Large.KaratsubaCutoff)</c> that don't have a dedicated per-size impl
    /// (<see cref="Size1"/>..<see cref="Size10"/>). Counterpart to
    /// <see cref="MediumOdd"/>, which handles odd <c>m_size</c> in the same range.
    /// </summary>
    /// <remarks>
    /// Multiply is a single stackalloc + <see cref="Kernels.ImplMulEven"/> + reduce.
    /// The kernel views the operand ulong spans as <c>Vector128&lt;ulong&gt;</c> "limbs"
    /// (each V128 = 2 packed ulongs) and runs a flat arbitrary-degree single-level
    /// Karatsuba: <c>L = m_size / 2</c> diagonal sub-multiplies plus <c>L*(L-1)/2</c>
    /// cross-product sub-multiplies, each a <c>Mul2x2</c> on V128 limbs. Direct analog
    /// of the scalar arbitrary-degree kernel. The upper bound
    /// (<see cref="Large.KaratsubaCutoff"/>) is where the O(L^2) flat structure loses to
    /// the recursive Karatsuba descent in <see cref="Large"/>.
    /// </remarks>
    internal sealed class MediumEven
        : BinPolyMulBase
    {
        internal MediumEven(int n, IReduce reduce)
            : base(n, reduce)
        {
            Debug.Assert((m_size & 1) == 0 && m_size >= 12 && m_size < Large.KaratsubaCutoff);
            Debug.Assert(m_sizeExt <= StackAllocCutoff);
        }

        public override void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            Span<ulong> tt = stackalloc ulong[m_sizeExt];
            Kernels.ImplMulEven(x.AsSpan(xOff, m_size), y.AsSpan(yOff, m_size), tt);
            m_reduce.Reduce(tt, z.AsSpan(zOff, m_size));
            BinPolys.Clear(m_sizeExt, tt);
        }
    }
}
#endif
