using System.Diagnostics;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.BinPoly.Scalar
{
    /// <summary>
    /// Scalar leaf multiply for the non-CLMUL fallback backend, used when PCLMUL is not
    /// available (<c>net461</c> / <c>netstandard2.0</c>, or <c>netcoreapp3+</c> with
    /// PCLMULQDQ disabled). Arbitrary-degree Karatsuba with a 16-entry-table 1x1 multiply.
    /// </summary>
    /// <remarks>
    /// The table indexing has a data-dependent cache-line access pattern — a known
    /// cache-timing side channel inherent to the scalar fallback. Acceptable on platforms
    /// without CLMUL where there is no better option; the side-channel discipline is
    /// documented on <see cref="BinPolyMulBase"/>. Public surface is array+offset (no
    /// <c>Span</c>) so the same kernel compiles on TFMs without <c>System.Memory</c>.
    /// </remarks>
    internal static class Kernels
    {
        /// <summary>
        /// Leaf multiply: write <c>x[xOff..xOff + len - 1] * y[yOff..yOff + len - 1]</c>
        /// (carryless) into <c>zz[zzOff..zzOff + 2*len - 1]</c>, overwriting prior contents.
        /// </summary>
        internal static void ImplMul(int len, ulong[] x, int xOff, ulong[] y, int yOff,
            ulong[] zz, int zzOff)
        {
            // Probe operand and output bounds early so the caller gets a clean
            // IndexOutOfRangeException at the entry rather than mid-loop.
            var xBounds = x[xOff + len - 1];
            var yBounds = y[yOff + len - 1];
            var zzBounds = zz[zzOff + 2 * len - 1];

            // Diagonal phase overwrites each limb-pair via ImplMulw; the cross-product /
            // post-processing phase always XORs.
            ulong[] u = new ulong[16];

            for (int i = 0; i < len; ++i)
            {
                ImplMulw(u, x[xOff + i], y[yOff + i], zz, zzOff + (i << 1));
            }

            ImplMulPostprocess(len, x, xOff, y, yOff, zz, zzOff, u);
        }

        /// <summary>
        /// Post-processing shared by the leaf multiply: assumes the diagonal products
        /// <c>x_i * y_i</c> are already resident in <c>zz[zzOff + 2*i .. zzOff + 2*i + 1]</c>.
        /// XORs in the cross-product contributions and the streak fixup so that
        /// <c>zz[zzOff .. zzOff + 2*len - 1]</c> holds the full unreduced product. The 16-entry
        /// table <c>u</c> is reused as scratch.
        /// </summary>
        private static void ImplMulPostprocess(int len, ulong[] x, int xOff, ulong[] y, int yOff,
            ulong[] zz, int zzOff, ulong[] u)
        {
            ulong v0 = zz[zzOff], v1 = zz[zzOff + 1];
            for (int i = 1; i < len; ++i)
            {
                v0 ^= zz[zzOff + (i << 1)]; zz[zzOff + i] = v0 ^ v1; v1 ^= zz[zzOff + (i << 1) + 1];
            }

            ulong w = v0 ^ v1;
            Nat.Xor64(len, zz, zzOff, w, zz, zzOff + len);

            int last = len - 1;
            for (int zPos = 1; zPos < (last * 2); ++zPos)
            {
                int hi = System.Math.Min(last, zPos);
                int lo = zPos - hi;

                while (lo < hi)
                {
                    ImplMulwAcc(u, x[xOff + lo] ^ x[xOff + hi], y[yOff + lo] ^ y[yOff + hi],
                        zz, zzOff + zPos);

                    ++lo;
                    --hi;
                }
            }
        }

        /// <summary>
        /// 1x1 carryless multiply of <c>x</c> and <c>y</c> into <c>z[zOff..zOff+1]</c>,
        /// overwriting prior contents. Builds a 16-entry table lazily in <c>u</c>. Used by
        /// the diagonal phase of <see cref="ImplMul"/>.
        /// </summary>
        private static void ImplMulw(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
        {
            ulong h = 0, m = x, n = y;

            //u[0] = 0UL;
            u[1] = y;
            for (int i = 2; i < 16; i += 2)
            {
                ulong u_i = u[i / 2] << 1;
                u[i    ] = u_i;
                u[i + 1] = u_i ^ y;

                // Interleave "repair" steps here for performance.
                m = (m & 0xFEFEFEFEFEFEFEFEUL) >> 1;
                h ^= m & (ulong)((long)n >> 63);
                n <<= 1;
            }

            uint j = (uint)x;
            ulong g, l = u[j & 15]
                       ^ u[(j >> 4) & 15] << 4;
            int k = 56;
            do
            {
                j  = (uint)(x >> k);
                g  = u[j & 15]
                   ^ u[(j >> 4) & 15] << 4;
                l ^= g << k;
                h ^= g >> -k;
            }
            while ((k -= 8) > 0);

            Debug.Assert(h >> 63 == 0);

            z[zOff    ] = l;
            z[zOff + 1] = h;
        }

        /// <summary>
        /// 1x1 carryless multiply-accumulate of <c>x</c> and <c>y</c> into
        /// <c>z[zOff..zOff+1]</c> via a 16-entry table built lazily in <c>u</c>. Used by the
        /// cross-product phase of <see cref="ImplMulPostprocess"/>.
        /// </summary>
        private static void ImplMulwAcc(ulong[] u, ulong x, ulong y, ulong[] z, int zOff)
        {
            ulong h = 0, m = x, n = y;

            //u[0] = 0UL;
            u[1] = y;
            for (int i = 2; i < 16; i += 2)
            {
                ulong u_i = u[i / 2] << 1;
                u[i    ] = u_i;
                u[i + 1] = u_i ^ y;

                // Interleave "repair" steps here for performance.
                m = (m & 0xFEFEFEFEFEFEFEFEUL) >> 1;
                h ^= m & (ulong)((long)n >> 63);
                n <<= 1;
            }

            uint j = (uint)x;
            ulong g, l = u[j & 15]
                       ^ u[(j >> 4) & 15] << 4;
            int k = 56;
            do
            {
                j  = (uint)(x >> k);
                g  = u[j & 15]
                   ^ u[(j >> 4) & 15] << 4;
                l ^= g << k;
                h ^= g >> -k;
            }
            while ((k -= 8) > 0);

            Debug.Assert(h >> 63 == 0);

            z[zOff    ] ^= l;
            z[zOff + 1] ^= h;
        }
    }
}
