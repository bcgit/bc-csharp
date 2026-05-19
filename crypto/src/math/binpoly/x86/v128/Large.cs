#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Diagnostics;

using static Org.BouncyCastle.Math.BinPoly.X86.V128.Kernels;

namespace Org.BouncyCastle.Math.BinPoly.X86.V128
{
    /// <summary>
    /// Sealed <see cref="IBinPolyMul"/> impl selected for sizes at or above the PCLMUL
    /// <see cref="KaratsubaCutoff"/>. Implements multiplication via a Karatsuba recursion
    /// that bottoms out via <see cref="ImplLeaf"/> into the uniform <c>ImplMulEven</c> /
    /// <c>ImplMulOdd</c> arbitrary-degree-Karatsuba leaf (by even/odd length). The class
    /// name reflects the dispatch criterion (large operand size); the algorithm inside is
    /// Karatsuba.
    /// </summary>
    /// <remarks>
    /// Internally <see cref="Span{T}"/>-based: the public array+offset <see cref="Multiply"/>
    /// entry converts to <see cref="ReadOnlySpan{T}"/> / <see cref="Span{T}"/> at the top of
    /// the call and the recursion uses <c>Span.Slice(...)</c> throughout. The CLMUL-only TFM
    /// guard (<c>NETCOREAPP3_0_OR_GREATER</c>) makes this safe — Spans are always available
    /// where this class compiles. The recursion's scratch buffer is allocated per
    /// <see cref="Multiply"/> call and threaded through as a parameter, so instances are
    /// safe to use concurrently.
    /// </remarks>
    internal sealed class Large
        : BinPolyMulBase
    {
        // Karatsuba cutoff (in machine words). Below this, the leaf multiply is called
        // directly via ImplLeaf; above it, ImplKaratsuba recurses by halving. Must be >= 2:
        // ImplKaratsuba and KaratsubaScratchSize both halve via (len + 1) >> 1, whose fixed
        // point is len = 1, so len < KaratsubaCutoff must hold at len = 1 for the recursion /
        // loop to terminate.
        //
        // Tuned empirically against Bench_PerfGraph_Binomial_Multiply (BIKE-1/3/5,
        // HQC-128/192/256). Picked at 32 by the 2026-05-27 downward re-probe (see
        // project_binpoly_followups memory) after the V128-Karatsuba leaf uniformization
        // (ImplMulEven / ImplMulOdd everywhere via ImplLeaf): with the leaf now a flat
        // single-level Karatsuba scaling ~3L^2/2 PCLMULs in L V128 limbs, dropping the
        // cutoff lets bike5 (-4.3%), hqc192 (-4.0%) and hqc128 (-1.7%) descend one more
        // Karatsuba level to leaves at {20,21} / {17,18} respectively. Cutoff=32 sits in
        // the middle of the [30, 34] descent-equivalence plateau (all six bench sizes
        // descend identically across that range); going below to cutoff <= 29 regresses
        // hqc256 (+3%) because its {28,29} leaves split to {14,15} and the 3-recursion
        // overhead now exceeds the leaf-cost saving.
        //
        // Exposed as 'internal' so Backend.CreateBinPolyMul can use it to pick the
        // mid-band impls (MediumEven / MediumOdd) vs Large at dispatch time.
        internal const int KaratsubaCutoff = 32;

        internal Large(int n, IReduce reduce)
            : base(n, reduce)
        {
        }

        public override void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            int scratchSize = KaratsubaScratchSize(m_size);
            int rentSize = m_sizeExt + scratchSize;
            ulong[] combined = m_scratchPool.Rent(rentSize);
            try
            {
                var tt = combined.AsSpan(0, m_sizeExt);
                var scratch = combined.AsSpan(m_sizeExt, scratchSize);
                ImplKaratsuba(x.AsSpan(xOff, m_size), y.AsSpan(yOff, m_size), tt, scratch);
                m_reduce.Reduce(tt, z.AsSpan(zOff, m_size));
            }
            finally
            {
                BinPolys.Clear(rentSize, combined, 0);
                m_scratchPool.Return(combined);
            }
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
        /// (<c>scratch.Slice(2m)</c>) to its child sub-calls. Name keeps Karatsuba because
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
        /// Leaf dispatch for the Karatsuba recursion base case (<c>x.Length &lt;
        /// KaratsubaCutoff</c>). Even lengths go through <c>ImplMulEven</c>, odd
        /// lengths through <c>ImplMulOdd</c> -- both arbitrary-degree Karatsuba
        /// over <c>Vector128&lt;ulong&gt;</c> limbs, with the odd kernel handling
        /// the half-V128 tail in registers.
        /// </summary>
        /// <remarks>
        /// Reachable lengths here are the Karatsuba leaf range <c>[16, 31]</c> (one halving
        /// below the PCLMUL cutoff of 32). All sub-cutoff top-level sizes route to other
        /// impls (<see cref="Size1"/>..<see cref="Size10"/>, <see cref="MediumEven"/>,
        /// or <see cref="MediumOdd"/>) and never reach this leaf. The even/odd split
        /// here mirrors the <see cref="MediumEven"/> / <see cref="MediumOdd"/> split
        /// at the top-level dispatch and calls the same kernels.
        /// </remarks>
        private static void ImplLeaf(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            if ((x.Length & 1) == 0)
            {
                ImplMulEven(x, y, zz);
            }
            else
            {
                ImplMulOdd(x, y, zz);
            }
        }

        /// <summary>
        /// Recursive Karatsuba multiply (Span-based). Writes
        /// <c>x[0..x.Length-1] * y[0..x.Length-1]</c> (carryless) into
        /// <c>zz[0..2*x.Length-1]</c>, overwriting prior contents. The
        /// <paramref name="scratch"/> span is sized once at the entry call
        /// (<see cref="KaratsubaScratchSize"/> for <c>m_size</c>); each frame parks its
        /// <c>zMid</c> output at <c>scratch[0..2m)</c> and recurses with
        /// <c>scratch.Slice(2m)</c>, so frames stack disjointly along the descent. The
        /// <c>ta</c> / <c>tb</c> halving-sums are written into the parent's <c>zz</c>
        /// region (where <c>z0</c> / <c>z2</c> will eventually live) and are overwritten
        /// by the <c>z0</c> / <c>z2</c> sub-calls. Sub-product slots are always
        /// overwritten by the recursive calls, so the caller need not pre-zero
        /// <paramref name="scratch"/>.
        /// </summary>
        /// <remarks>
        /// <para>The recombine reads every limb of the <c>zMid</c> output
        /// (<c>scratch[0..2m)</c>), so the <c>zMid</c> sub-call must write every output
        /// limb. Both leaves do (<c>ImplMulEven</c> writes every V128 lane;
        /// <c>ImplMulOdd</c> writes every lane within its <c>2*len</c>-ulong contract,
        /// with the tail-V128 zero-fill handled implicitly via the diagonal phase's
        /// single PCLMULQDQ). A future leaf that elides a slack-only limb would have
        /// to either restrict the contract to "writes all limbs" or add per-frame
        /// defensive zeroing here.</para>
        /// </remarks>
        private static void ImplKaratsuba(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y,
            Span<ulong> zz, Span<ulong> scratch)
        {
            int len = x.Length;
            if (len < KaratsubaCutoff)
            {
                ImplLeaf(x, y, zz);
                return;
            }

            if ((len & 1) == 0)
            {
                int m = len >> 1;

                // This frame's zMid output lives at scratch[0..2m); childScratch is the
                // suffix (scratch.Slice(2m)) passed to every sub-call. ta + tb go into
                // zz's z0 region (zz[0..2m)) and are overwritten by the z0 / z2 sub-calls
                // before the recombine reads zz.
                var childScratch = scratch.Slice(2 * m);

                // ta = x_lo + x_hi -> zz[..m), tb = y_lo + y_hi -> zz[m..2m).
                for (int i = 0; i < m; ++i)
                {
                    zz[i]     = x[i] ^ x[m + i];
                    zz[m + i] = y[i] ^ y[m + i];
                }

                // zMid = ta * tb -> scratch[..len)
                ImplKaratsuba(zz.Slice(0, m), zz.Slice(m, m), scratch.Slice(0, len), childScratch);

                // z0 = x_lo * y_lo -> zz[..len) (overwriting ta + tb).
                ImplKaratsuba(x.Slice(0, m), y.Slice(0, m), zz.Slice(0, len), childScratch);
                // z2 = x_hi * y_hi -> zz[len..2*len).
                ImplKaratsuba(x.Slice(m, m), y.Slice(m, m), zz.Slice(len, len), childScratch);

                // Recombine in a single fused pass. Each iteration pairs the lower-middle
                // write at zz[m + i] with the upper-middle write at zz[len + i] = zz[2m + i];
                // the common term u = z0[m+i] ^ z2[i] is read out of zz before either store
                // lands.
                for (int i = 0; i < m; ++i)
                {
                    ulong u = zz[m + i] ^ zz[len + i];
                    zz[m + i] = u ^ zz[i] ^ scratch[i];
                    zz[len + i] = u ^ zz[len + m + i] ^ scratch[m + i];
                }
            }
            else
            {
                int n = len >> 1;           // small half
                int m = n + 1;              // big half; len = m + n = 2m - 1
                int nx2 = n << 1;
                int mx2 = m << 1;

                // This frame's zMid output lives at scratch[0..mx2); childScratch is the
                // suffix passed to every sub-call. ta + tb go into zz[0..2m): ta in
                // zz[..m), tb in zz[m..2m). The last 2 limbs of that 2m-window sit inside
                // z2's eventual range — z0 + z2 together overwrite all of zz[0..2m)
                // before the recombine reads zz.
                var childScratch = scratch.Slice(mx2);

                // ta = x_lo + x_hi -> zz[..m); x_lo zero-padded to m at index n. tb similar.
                for (int i = 0; i < n; ++i)
                {
                    zz[i]     = x[i] ^ x[n + i];
                    zz[m + i] = y[i] ^ y[n + i];
                }
                zz[n]     = x[nx2];
                zz[m + n] = y[nx2];

                // zMid = ta * tb -> scratch[..mx2)
                ImplKaratsuba(zz.Slice(0, m), zz.Slice(m, m), scratch.Slice(0, mx2), childScratch);

                // z0 = x_lo * y_lo (n-limb) -> zz[..nx2).
                ImplKaratsuba(x.Slice(0, n), y.Slice(0, n), zz.Slice(0, nx2), childScratch);
                // z2 = x_hi * y_hi (m-limb) -> zz[nx2..nx2 + mx2).
                ImplKaratsuba(x.Slice(n, m), y.Slice(n, m), zz.Slice(nx2, mx2), childScratch);

                // Fused recombination main loop — analogous to the even branch, paired
                // writes to the lower middle (zz[n+i]) and upper middle (zz[nx2+i]).
                for (int i = 0; i < n; ++i)
                {
                    ulong u = zz[n + i] ^ zz[nx2 + i];
                    zz[n + i] = u ^ zz[i] ^ scratch[i];
                    zz[nx2 + i] = u ^ zz[nx2 + n + i] ^ scratch[n + i];
                }

                // Tail (i = nx2 and i = nx2 + 1 of the formula above): the last 2 positions
                // of the middle range sit past z0's length, so the recombination collapses
                // to (zMid ^ z2) for these.
                zz[n + nx2    ] ^= scratch[nx2    ] ^ zz[nx2 + nx2    ];
                zz[n + nx2 + 1] ^= scratch[nx2 + 1] ^ zz[nx2 + nx2 + 1];
            }
        }
    }
}
#endif
