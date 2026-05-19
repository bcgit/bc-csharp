using System.Diagnostics;

namespace Org.BouncyCastle.Math.BinPoly.Scalar
{
    /// <summary>
    /// Sealed <see cref="IBinPolyMul"/> impl selected (alongside <see cref="Medium"/>) on the
    /// scalar backend when PCLMUL is not available (<c>net461</c> / <c>netstandard2.0</c>,
    /// or <c>netcoreapp3+</c> with PCLMULQDQ disabled). Picked for sizes at or above
    /// <see cref="KaratsubaCutoff"/>; smaller sizes route to <see cref="Medium"/> instead.
    /// Implements multiplication via an in-class Karatsuba recursion whose leaf is the
    /// scalar 16-entry-table <see cref="Kernels.ImplMul"/>. The class name reflects the
    /// dispatch criterion (large operand size); the algorithm inside is Karatsuba.
    /// </summary>
    /// <remarks>
    /// <para>There is no scalar analogue of the X86.V128 size-N or block kernels — the
    /// scalar leaf is always <see cref="Kernels.ImplMul"/>. The cache-timing side channel
    /// inherent to the scalar fallback is documented on <see cref="BinPolyMulBase"/>.</para>
    /// <para>The recursion's scratch buffer is allocated per <see cref="Multiply"/> call and
    /// threaded through as a parameter, so instances are safe to use concurrently.</para>
    /// </remarks>
    internal sealed class Large
        : BinPolyMulBase
    {
        // Karatsuba cutoff (in machine words). Below this, the leaf multiply (the scalar
        // 16-entry-table ImplMul) is called directly via ImplLeaf; above it, ImplKaratsuba
        // recurses by halving. Must be >= 2 for recursion termination (see X86.V128.Large
        // for the rationale). Empirically tuned at 8 for the table-based scalar leaf (probe
        // with DOTNET_EnableHWIntrinsic=0); full tuning history is in the
        // project_binpoly_followups memory.
        //
        // Exposed as 'internal' so Backend.CreateBinPolyMul can use it to pick Medium vs
        // Large at dispatch time.
        internal const int KaratsubaCutoff = 8;

        internal Large(int n, IReduce reduce)
            : base(n, reduce)
        {
        }

        public override void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            int scratchSize = KaratsubaScratchSize(m_size);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int rentSize = m_sizeExt + scratchSize;
            ulong[] combined = m_scratchPool.Rent(rentSize);
            try
            {
                ImplKaratsuba(m_size, x, xOff, y, yOff, combined, 0, combined, m_sizeExt);
                m_reduce.Reduce(combined, 0, z, zOff);
            }
            finally
            {
                BinPolys.Clear(rentSize, combined, 0);
                m_scratchPool.Return(combined);
            }
#else
            ulong[] tt = new ulong[m_sizeExt];
            ulong[] scratch = new ulong[scratchSize];
            ImplKaratsuba(m_size, x, xOff, y, yOff, tt, 0, scratch, 0);
            BinPolys.Clear(scratchSize, scratch, 0);
            m_reduce.Reduce(tt, 0, z, zOff);
            BinPolys.Clear(m_sizeExt, tt, 0);
#endif
        }

        /// <summary>
        /// Words of scratch space the top-level <see cref="Multiply"/> entry must allocate
        /// for an <see cref="ImplKaratsuba"/> call over an operand of length
        /// <paramref name="len"/>. Computed by walking the halving chain from
        /// <paramref name="len"/> down to the cutoff: each level contributes
        /// <c>2 * ceil(len/2)</c> for that frame's <c>zMid</c> output slot. The
        /// <c>ta</c> / <c>tb</c> halving-sums reuse the parent's <c>zz</c> output region
        /// (pre-overwrite by <c>z0</c> / <c>z2</c>), so they need no scratch of their
        /// own. Frames stack consecutively from offset 0 upward — each parent claims the
        /// first <c>2m</c> words of its scratch view and hands the suffix
        /// (<c>scratchOff + 2m</c>) to its child sub-calls. Name keeps Karatsuba because
        /// the scratch layout is intrinsic to the Karatsuba recombination shape.
        /// </summary>
        private static int KaratsubaScratchSize(int len)
        {
            Debug.Assert(KaratsubaCutoff >= 2);

            int total = 0;
            while (len >= KaratsubaCutoff)
            {
                len = (len + 1) >> 1;
                total += len;
            }
            return total << 1;
        }

        /// <summary>
        /// Leaf dispatch for the Karatsuba recursion base case
        /// (<c>len &lt; KaratsubaCutoff</c>). No scalar-specific size kernels — every leaf
        /// length funnels through the table-based <see cref="Kernels.ImplMul"/>.
        /// </summary>
        private static void ImplLeaf(int len, ulong[] x, int xOff, ulong[] y, int yOff,
            ulong[] zz, int zzOff)
        {
            Kernels.ImplMul(len, x, xOff, y, yOff, zz, zzOff);
        }

        /// <summary>
        /// Recursive Karatsuba multiply. Writes <c>x[0..len-1] * y[0..len-1]</c> (carryless)
        /// into <c>zz[0..2*len-1]</c>, overwriting prior contents. The shared
        /// <paramref name="scratch"/> array is sized once at the entry call
        /// (<see cref="KaratsubaScratchSize"/> for <c>m_size</c>); each frame parks its
        /// <c>zMid</c> output at <c>scratch[scratchOff..scratchOff + 2m)</c> and recurses
        /// with <c>scratchOff + 2m</c>, so frames stack disjointly from low offsets to
        /// high. The <c>ta</c> / <c>tb</c> halving-sums are written into the parent's
        /// <c>zz</c> region (where <c>z0</c> / <c>z2</c> will eventually live) and are
        /// overwritten by the <c>z0</c> / <c>z2</c> sub-calls — no scratch slot needed
        /// for them. Sub-product slots are always overwritten by the recursive calls, so
        /// the caller need not pre-zero <paramref name="scratch"/>.
        /// </summary>
        /// <remarks>
        /// <para>The recombine reads every limb of the <c>zMid</c> output (the
        /// <c>scratch.Slice(zMidOffset, 2m)</c> slot), so the <c>zMid</c> sub-call must
        /// write every output limb. All current leaves do (size-general schoolbook
        /// clears its output range before accumulating; per-size kernels write every
        /// lane; scalar table-based <c>ImplMul</c>'s diagonal phase writes every
        /// limb-pair). A future leaf optimisation that elides a slack-only limb would
        /// break this — it would have to either restrict the contract to "writes all
        /// limbs" or add per-frame defensive zeroing here.</para>
        /// </remarks>
        private static void ImplKaratsuba(int len, ulong[] x, int xOff, ulong[] y, int yOff,
            ulong[] zz, int zzOff, ulong[] scratch, int scratchOff)
        {
            if (len < KaratsubaCutoff)
            {
                ImplLeaf(len, x, xOff, y, yOff, zz, zzOff);
                return;
            }

            if ((len & 1) == 0)
            {
                int m = len >> 1;

                int zMidOffset = scratchOff;
                int childScratchOff = scratchOff + 2 * m;

                // ta = x_lo + x_hi -> zz[zzOff..zzOff+m), tb = y_lo + y_hi -> zz[zzOff+m..zzOff+2m).
                // These positions are zz's z0 region — z0 / z2 will overwrite them later.
                for (int i = 0; i < m; ++i)
                {
                    zz[zzOff + i]     = x[xOff + i] ^ x[xOff + m + i];
                    zz[zzOff + m + i] = y[yOff + i] ^ y[yOff + m + i];
                }

                // zMid = ta * tb -> scratch[zMidOffset..zMidOffset+len)
                ImplKaratsuba(m, zz, zzOff, zz, zzOff + m,
                    scratch, zMidOffset, scratch, childScratchOff);

                // z0 = x_lo * y_lo -> zz[zzOff..zzOff+len) (overwriting ta + tb).
                ImplKaratsuba(m, x, xOff, y, yOff, zz, zzOff, scratch, childScratchOff);
                // z2 = x_hi * y_hi -> zz[zzOff+len..zzOff+2*len).
                ImplKaratsuba(m, x, xOff + m, y, yOff + m, zz, zzOff + len,
                    scratch, childScratchOff);

                for (int i = 0; i < m; ++i)
                {
                    ulong u = zz[zzOff + m + i] ^ zz[zzOff + len + i];
                    zz[zzOff + m + i] = u ^ zz[zzOff + i] ^ scratch[zMidOffset + i];
                    zz[zzOff + len + i] = u ^ zz[zzOff + len + m + i] ^ scratch[zMidOffset + m + i];
                }
            }
            else
            {
                int n = len >> 1;
                int m = n + 1;
                int nx2 = n << 1;
                int mx2 = m << 1;

                int zMidOffset = scratchOff;
                int childScratchOff = scratchOff + mx2;

                // ta = x_lo + x_hi -> zz[zzOff..zzOff+m); x_lo zero-padded to m at index n.
                // tb similar at zz[zzOff+m..zzOff+2m). The last 2 limbs of this 2m-window
                // sit inside z2's eventual range; z0 + z2 together overwrite the whole
                // 2m-window before the recombine reads zz.
                for (int i = 0; i < n; ++i)
                {
                    zz[zzOff + i]     = x[xOff + i] ^ x[xOff + n + i];
                    zz[zzOff + m + i] = y[yOff + i] ^ y[yOff + n + i];
                }
                zz[zzOff + n]     = x[xOff + nx2];
                zz[zzOff + m + n] = y[yOff + nx2];

                // zMid = ta * tb -> scratch[zMidOffset..zMidOffset+mx2)
                ImplKaratsuba(m, zz, zzOff, zz, zzOff + m,
                    scratch, zMidOffset, scratch, childScratchOff);

                // z0 = x_lo * y_lo (n-limb) -> zz[zzOff..zzOff+nx2).
                ImplKaratsuba(n, x, xOff, y, yOff, zz, zzOff, scratch, childScratchOff);
                // z2 = x_hi * y_hi (m-limb) -> zz[zzOff+nx2..zzOff+nx2+mx2).
                ImplKaratsuba(m, x, xOff + n, y, yOff + n, zz, zzOff + nx2,
                    scratch, childScratchOff);

                for (int i = 0; i < n; ++i)
                {
                    ulong u = zz[zzOff + n + i] ^ zz[zzOff + nx2 + i];
                    zz[zzOff + n + i] = u ^ zz[zzOff + i] ^ scratch[zMidOffset + i];
                    zz[zzOff + nx2 + i] = u ^ zz[zzOff + nx2 + n + i] ^ scratch[zMidOffset + n + i];
                }

                zz[zzOff + n + nx2    ] ^= scratch[zMidOffset + nx2    ] ^ zz[zzOff + nx2 + nx2    ];
                zz[zzOff + n + nx2 + 1] ^= scratch[zMidOffset + nx2 + 1] ^ zz[zzOff + nx2 + nx2 + 1];
            }
        }
    }
}
