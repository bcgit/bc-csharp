#if NETCOREAPP3_0_OR_GREATER
using System;

namespace Org.BouncyCastle.Math.BinPoly.X86.V128
{
    /// <summary>
    /// Entry point for the X86.V128 backend: an <see cref="IsEnabled"/> gate and a
    /// <see cref="CreateBinPolyMul"/> factory that picks the most specialised
    /// <see cref="IBinPolyMul"/> impl for the requested polynomial size. Decouples
    /// <see cref="BinPolys"/>'s dispatch from the backend's own gate condition — the
    /// outer dispatch just asks "are you applicable?" and "give me an instance".
    /// </summary>
    internal static class Backend
    {
        /// <summary>
        /// True when this backend's prerequisites hold on the current runtime — currently
        /// the project's <c>Pclmulqdq</c> wrapper (which depends on SSE2). The check is
        /// JIT-folded.
        /// </summary>
        internal static bool IsEnabled =>
            Org.BouncyCastle.Runtime.Intrinsics.X86.Pclmulqdq.IsEnabled;

        /// <summary>
        /// Pick the most specialised <see cref="IBinPolyMul"/> impl for the given size:
        /// fixed-size (<see cref="Size1"/>..<see cref="Size10"/>),
        /// <see cref="MediumEven"/> / <see cref="MediumOdd"/> (flat arbitrary-degree
        /// Karatsuba over Vector128 limbs, MediumOdd handling the half-V128 tail
        /// for odd m_size) for the mid-band, or <see cref="Large"/> (recursive
        /// Karatsuba over ulong) for size at or above the cutoff. Throws if
        /// <see cref="IsEnabled"/> is false rather than handing back an instance
        /// that would fail later inside an intrinsic call.
        /// </summary>
        internal static IBinPolyMul CreateBinPolyMul(int n, BinPolyMulBase.IReduce reduce)
        {
            if (!IsEnabled)
                throw new InvalidOperationException(
                    "X86.V128 backend requires Pclmulqdq support on this runtime.");

            int size = BinPolys.Size(n);
            switch (size)
            {
            case  1: return new Size1 (n, reduce);
            case  2: return new Size2 (n, reduce);
            case  3: return new Size3 (n, reduce);
            case  4: return new Size4 (n, reduce);
            case  5: return new Size5 (n, reduce);
            case  6: return new Size6 (n, reduce);
            case  7: return new Size7 (n, reduce);
            case  8: return new Size8 (n, reduce);
            case  9: return new Size9 (n, reduce);
            case 10: return new Size10(n, reduce);
            }
            if (size >= Large.KaratsubaCutoff)
                return new Large(n, reduce);
            if ((size & 1) == 0)
                return new MediumEven(n, reduce);
            return new MediumOdd(n, reduce);
        }
    }
}
#endif
