using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif
using System.Diagnostics;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.BinPoly
{
    /// <summary>
    /// Abstract base for <see cref="IBinPolyMul"/> implementations. Holds the shared state
    /// (<c>m_n</c>, <c>m_size</c>, <c>m_sizeExt</c>, <c>m_reduce</c>) and the squaring
    /// helpers (<c>Square</c>, <c>SquareN</c>). <see cref="Multiply"/> is abstract and is
    /// supplied by per-(size, ISA) concrete subclasses.
    /// </summary>
    /// <remarks>
    /// <para>Polynomials are stored bit-packed in <c>ulong[]</c> with little-endian word order.
    /// The caller is responsible for size-checking buffer arguments.</para>
    /// <para>The leaf multiply (below the Karatsuba recursion cutoff) is arbitrary-degree
    /// Karatsuba in both backends: over <c>Vector128&lt;ulong&gt;</c> limbs via <c>PCLMULQDQ</c> when
    /// available (gated by the project wrapper at
    /// <see cref="Org.BouncyCastle.Runtime.Intrinsics.X86.Pclmulqdq"/>), otherwise over words with a
    /// 16-entry-table 1x1 multiply.</para>
    /// <para>The scalar fallback's 16-entry table is small (128 bytes, single cache line on x86)
    /// but is indexed by 4 bits of one operand, so the fallback has a known cache-timing side
    /// channel. If the caller's threat model includes cache-timing attackers, deployment must
    /// ensure PCLMULQDQ is available.</para>
    /// <para>The implementation is split across several partial files: <c>BinPolyMulBase.cs</c>
    /// holds the shared state and reducer plumbing (<see cref="IReduce"/>, <see cref="Pos"/>,
    /// <see cref="DebugAssertReducePreconditions(int, ulong[], int)"/>); <c>BinPolyMulBase.Binomial.cs</c>,
    /// <c>BinPolyMulBase.Trinomial.cs</c> and <c>BinPolyMulBase.Pentanomial.cs</c> contain
    /// the three reducer families. Leaf-multiply kernels live in per-backend static
    /// containers: <c>X86.V128.Kernels</c> (CLMUL, split across <c>x86/v128/Kernels.Small.cs</c>
    /// and <c>x86/v128/Kernels.Medium.cs</c>) and <c>Scalar.Kernels</c> (table-based, in
    /// <c>scalar/Kernels.cs</c>).</para>
    /// </remarks>
    internal abstract partial class BinPolyMulBase
        : IBinPolyMul
    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // Cutoff (in ulongs) below which Multiply / Square / SquareN stackalloc tt
        // instead of renting from m_scratchPool. 128 ulongs = 1024 bytes, sitting
        // right at the "polite stackalloc" 1 KB convention rather than comfortably
        // below it -- the alternative is a pool-rent latency on every Medium-band
        // call. Covers all SECT-curve sizes and the full X86.V128 Medium m_size
        // range up to m_size = 63 (m_sizeExt = 126, one V128 of headroom).
        internal const int StackAllocCutoff = 128;

        // Private pool for the combined tt + scratch buffer rented by Large.Multiply on
        // both backends. Buffers carry secret-bearing partial products, so we use Create()
        // rather than Shared to keep them out of the process-wide pool.
        internal static readonly ArrayPool<ulong> m_scratchPool = ArrayPool<ulong>.Create();
#endif

        protected readonly int m_n;
        protected readonly int m_size;
        // m_sizeExt is always 2 * m_size. This is a deliberate simplification: an extended product
        // of two m_n-bit polynomials fits in 2*m_n - 1 bits, so the topmost limb of the extended
        // buffer may carry only a few bits, but the wasted single limb is preferable to the extra
        // conditional logic that would be required to track a tighter bound.
        protected readonly int m_sizeExt;
        protected readonly IReduce m_reduce;

        protected BinPolyMulBase(int n, IReduce reduce)
        {
            m_n = n;
            m_size = BinPolys.Size(n);
            m_sizeExt = m_size * 2;
            m_reduce = reduce;
        }

        // ----- Properties / allocation -----

        public int N => m_n;
        public int Size => m_size;

        // ----- Arithmetic (all-modular: inputs and outputs are reduced) -----

        public abstract void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff);

        public void Square(ulong[] x, int xOff, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (m_sizeExt <= StackAllocCutoff)
            {
                Span<ulong> tt = stackalloc ulong[m_sizeExt];
                Interleave.Expand64To128(x.AsSpan(xOff, m_size), tt);
                m_reduce.Reduce(tt, z.AsSpan(zOff, m_size));
                BinPolys.Clear(m_sizeExt, tt);
            }
            else
            {
                ulong[] tt = m_scratchPool.Rent(m_sizeExt);
                try
                {
                    Interleave.Expand64To128(x, xOff, m_size, tt, 0);
                    m_reduce.Reduce(tt, 0, z, zOff);
                }
                finally
                {
                    BinPolys.Clear(m_sizeExt, tt, 0);
                    m_scratchPool.Return(tt);
                }
            }
#else
            ulong[] tt = new ulong[m_sizeExt];
            Interleave.Expand64To128(x, xOff, m_size, tt, 0);
            m_reduce.Reduce(tt, 0, z, zOff);
            BinPolys.Clear(m_sizeExt, tt, 0);
#endif
        }

        public void SquareN(ulong[] x, int xOff, int n, ulong[] z, int zOff)
        {
            if (n < 1)
                throw new ArgumentOutOfRangeException(nameof(n), "must be positive");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (m_sizeExt <= StackAllocCutoff)
            {
                Span<ulong> tt = stackalloc ulong[m_sizeExt];
                var zSpan = z.AsSpan(zOff, m_size);
                Interleave.Expand64To128(x.AsSpan(xOff, m_size), tt);
                m_reduce.Reduce(tt, zSpan);

                while (--n > 0)
                {
                    Interleave.Expand64To128(zSpan, tt);
                    m_reduce.Reduce(tt, zSpan);
                }

                BinPolys.Clear(m_sizeExt, tt);
            }
            else
            {
                ulong[] tt = m_scratchPool.Rent(m_sizeExt);
                try
                {
                    Interleave.Expand64To128(x, xOff, m_size, tt, 0);
                    m_reduce.Reduce(tt, 0, z, zOff);

                    while (--n > 0)
                    {
                        Interleave.Expand64To128(z, zOff, m_size, tt, 0);
                        m_reduce.Reduce(tt, 0, z, zOff);
                    }
                }
                finally
                {
                    BinPolys.Clear(m_sizeExt, tt, 0);
                    m_scratchPool.Return(tt);
                }
            }
#else
            ulong[] tt = new ulong[m_sizeExt];
            Interleave.Expand64To128(x, xOff, m_size, tt, 0);
            m_reduce.Reduce(tt, 0, z, zOff);

            while (--n > 0)
            {
                Interleave.Expand64To128(z, zOff, m_size, tt, 0);
                m_reduce.Reduce(tt, 0, z, zOff);
            }

            BinPolys.Clear(m_sizeExt, tt, 0);
#endif
        }

        // ----- Reducer interface and shared helpers -----

        internal interface IReduce
        {
            /// <summary>
            /// Reduce the extended product in <c>tt[ttOff..ttOff + 2*size]</c> into
            /// <c>z[zOff..zOff + size]</c>. The reducer knows its own size.
            /// </summary>
            /// <remarks>
            /// <para>Post-condition on <c>tt</c>: <b>arbitrary</b>. The reducer may freely mutate any
            /// limb in its window, and individual implementations are free not to write some limbs
            /// at all (the fully-unrolled and direct-to-<c>z</c> variants do exactly this). Callers
            /// must not read <c>tt</c> after <c>Reduce</c> returns, and if <c>tt</c> held secret-
            /// bearing material they remain responsible for wiping it (see <c>BinPolys.Clear</c>).</para>
            /// </remarks>
            void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            /// <summary>
            /// <see cref="Span{T}"/> overload of <see cref="Reduce(ulong[], int, ulong[], int)"/>.
            /// Same contract; lengths come from the spans (<c>tt.Length</c> == 2 * size,
            /// <c>z.Length</c> == size). Used by the stack-allocated <c>tt</c> path in the X86.V128
            /// per-size wrappers.
            /// </summary>
            void Reduce(Span<ulong> tt, Span<ulong> z);
#endif
        }

        /// <summary>Decompose a bit position into its word index and bit offset within the word.</summary>
        private static void Pos(int bit, out int w, out int s)
        {
            w = bit >> 6;
            s = bit & 63;
        }

        /// <summary>
        /// Verify the per-call input contract of <see cref="IReduce.Reduce(ulong[], int, ulong[], int)"/>:
        /// <c>tt[ttOff..ttOff + 2*size]</c> must contain no bits at positions above <c>2n - 2</c>
        /// (the maximum degree producible by a product of two degree-&lt;n polynomials). The
        /// per-instance alignment precondition each reducer relies on (a partial top limb,
        /// <c>(n &amp; 63) != 0</c>, for the word-at-a-time variants) is asserted in the reducer
        /// constructors instead, since <c>n</c> is fixed at construction. Fully elided in Release
        /// builds.
        /// </summary>
        [Conditional("DEBUG")]
        private static void DebugAssertReducePreconditions(int n, ulong[] tt, int ttOff)
        {
            int sizeExt = BinPolys.Size(n) << 1;
            int slackBit = 2 * n - 1;
            int slackWord = slackBit >> 6;
            ulong slack = tt[ttOff + slackWord] >> (slackBit & 63);
            for (int i = slackWord + 1; i < sizeExt; ++i)
            {
                slack |= tt[ttOff + i];
            }
            Debug.Assert(slack == 0UL,
                "IReduce.Reduce: tt has bits set above position 2n-2; slack must be zero.");
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [Conditional("DEBUG")]
        private static void DebugAssertReducePreconditions(int n, Span<ulong> tt)
        {
            int sizeExt = BinPolys.Size(n) << 1;
            int slackBit = 2 * n - 1;
            int slackWord = slackBit >> 6;
            ulong slack = tt[slackWord] >> (slackBit & 63);
            for (int i = slackWord + 1; i < sizeExt; ++i)
            {
                slack |= tt[i];
            }
            Debug.Assert(slack == 0UL,
                "IReduce.Reduce: tt has bits set above position 2n-2; slack must be zero.");
        }
#endif
    }
}
