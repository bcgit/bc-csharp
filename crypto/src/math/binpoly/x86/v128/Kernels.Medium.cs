#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Org.BouncyCastle.Math.BinPoly.X86.V128
{
    internal static partial class Kernels
    {
        /// <summary>
        /// Arbitrary-degree single-level Karatsuba over <see cref="Vector128{T}"/> "limbs"
        /// (each V128 = 2 packed ulongs). Writes <c>x * y</c> (carryless) into
        /// <c>zz[0..2*x.Length)</c> where <c>x.Length</c> is the ulong-length of the
        /// operands and MUST be even (the kernel views x / y / zz as V128 spans of
        /// length <c>x.Length / 2</c> internally). Direct V128 analog of the scalar
        /// <c>Org.BouncyCastle.Math.BinPoly.Scalar.Kernels.ImplMul</c> arbitrary-degree
        /// pattern: <c>L</c> diagonal sub-multiplies plus <c>L*(L-1)/2</c> cross-product
        /// sub-multiplies (where <c>L = x.Length / 2</c>), all via <see cref="Mul2x2"/>,
        /// with the same streak-fixup that folds the <c>P_ii ^ P_jj</c> contributions
        /// across the output limbs.
        /// </summary>
        internal static void ImplMulEven(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            Debug.Assert((x.Length & 1) == 0 && x.Length >= 2);
            Debug.Assert(y.Length == x.Length);
            Debug.Assert(zz.Length == 2 * x.Length);

            var X = MemoryMarshal.Cast<ulong, Vector128<ulong>>(x);
            var Y = MemoryMarshal.Cast<ulong, Vector128<ulong>>(y);
            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            int len = X.Length;

            // Diagonal phase: ZZ[2i, 2i+1] = X[i] * Y[i] (overwrite).
            for (int i = 0; i < len; ++i)
            {
                Mul2x2(X[i], Y[i], out ZZ[i << 1], out ZZ[(i << 1) + 1]);
            }

            // Streak fixup: running XOR of diagonals folded into ZZ positions
            // [1, len) and [len, 2*len). After this, ZZ holds the "+P_ii^P_jj"
            // contributions for every output limb; the cross-product phase then
            // XORs raw Q_ij = (X_i ^ X_j)*(Y_i ^ Y_j) on top so each middle limb
            // ends up as M_ij = Q_ij ^ P_ii ^ P_jj.
            var V0 = ZZ[0];
            var V1 = ZZ[1];
            for (int i = 1; i < len; ++i)
            {
                V0 = Sse2.Xor(V0, ZZ[i << 1]);
                ZZ[i] = Sse2.Xor(V0, V1);
                V1 = Sse2.Xor(V1, ZZ[(i << 1) + 1]);
            }

            var W = Sse2.Xor(V0, V1);
            for (int i = 0; i < len; ++i)
            {
                ZZ[len + i] = Sse2.Xor(ZZ[i], W);
            }

            // Cross-product phase: enumerate all (lo, hi) with lo < hi by their sum
            // zPos = lo + hi, in [1, 2*last-1]. For each pair, XOR the 2-V128
            // product Q_lo_hi = (X_lo ^ X_hi) * (Y_lo ^ Y_hi) into ZZ[zPos, zPos+1].
            int last = len - 1;
            int doubleLast = last << 1;
            for (int zPos = 1; zPos < doubleLast; ++zPos)
            {
                int hi = System.Math.Min(last, zPos);
                int lo = zPos - hi;
                while (lo < hi)
                {
                    Mul2x2(Sse2.Xor(X[lo], X[hi]), Sse2.Xor(Y[lo], Y[hi]), out var W0, out var W1);
                    ZZ[zPos    ] = Sse2.Xor(ZZ[zPos    ], W0);
                    ZZ[zPos + 1] = Sse2.Xor(ZZ[zPos + 1], W1);
                    ++lo;
                    --hi;
                }
            }
        }

        /// <summary>
        /// Odd-length sibling of <see cref="ImplMulEven"/>. Writes <c>x * y</c>
        /// (carryless) into <c>zz[0..2*x.Length)</c> where <c>x.Length</c> is the
        /// ulong-length of the operands and MUST be odd. The high ulong of each
        /// operand is treated as the lower half of a virtual V128 limb whose upper
        /// half is zero -- so the kernel runs the same arbitrary-degree Karatsuba
        /// structure as ImplMulEven over <c>L + 1</c> virtual V128 limbs (where
        /// <c>L = x.Length / 2</c> full V128 limbs and the +1 is the tail).
        /// </summary>
        /// <remarks>
        /// <paramref name="zz"/> is sized to exactly <c>2 * x.Length</c> ulongs
        /// (same as ImplMulEven's contract). The tail-V128's upper half is known
        /// zero by construction, and the algorithm is arranged so no read or write
        /// ever touches the would-be-out-of-bounds <c>ZZ[2L + 1]</c> V128 lane: the
        /// tail diagonal writes only its low V128 via a single PCLMULQDQ, the split
        /// streak-fixup tail iteration drops the V1 update that would have read the
        /// zero, and the output pass stops one iteration short of writing past the
        /// real product range. Reads the tail ulong directly from
        /// <paramref name="x"/> / <paramref name="y"/> and synthesises the
        /// half-V128 tail in registers via <c>Vector128.Create(tail, 0)</c>.
        /// </remarks>
        internal static void ImplMulOdd(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            Debug.Assert((x.Length & 1) == 1 && x.Length >= 1);
            Debug.Assert(y.Length == x.Length);
            Debug.Assert(zz.Length == 2 * x.Length);

            int L = x.Length >> 1;  // full V128 limbs (x.Length = 2L + 1)
            int lenV = L + 1;       // virtual V128 length (tail = half-V128)

            // MemoryMarshal.Cast truncates: x / y give L V128 limbs each
            // (the tail ulong is dropped, re-read scalar-style into XL / YL below);
            // zz gives 2L + 1 V128 lanes (the last real product position; no
            // V128-of-slack at the top).
            var X = MemoryMarshal.Cast<ulong, Vector128<ulong>>(x);
            var Y = MemoryMarshal.Cast<ulong, Vector128<ulong>>(y);
            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);

            var XL = Vector128.Create(x[2 * L], 0UL);
            var YL = Vector128.Create(y[2 * L], 0UL);

            // Diagonal phase: full V128 limbs at i in [0..L), tail diagonal at i = L.
            // The tail product (XL * YL) is a single 128-bit value -- one PCLMULQDQ
            // -- not a full Mul2x2; the high V128 it would have written is dropped
            // since nothing reads it (see remarks).
            for (int i = 0; i < L; ++i)
            {
                Mul2x2(X[i], Y[i], out ZZ[i << 1], out ZZ[(i << 1) + 1]);
            }
            ZZ[L << 1] = Pclmulqdq.CarrylessMultiply(XL, YL, 0x00);

            // Streak fixup (otherwise identical to ImplMulEven). The first L iterations
            // match the even kernel exactly; the final i = L iteration is split out so
            // its V1 update can drop -- it would XOR in ZZ[2L + 1], which is past the
            // end of the output buffer and known zero by the tail-V128 construction.
            var V0 = ZZ[0];
            var V1 = ZZ[1];
            for (int i = 1; i < L; ++i)
            {
                V0 = Sse2.Xor(V0, ZZ[i << 1]);
                ZZ[i] = Sse2.Xor(V0, V1);
                V1 = Sse2.Xor(V1, ZZ[(i << 1) + 1]);
            }
            V0 = Sse2.Xor(V0, ZZ[L << 1]);
            ZZ[L] = Sse2.Xor(V0, V1);

            var W = Sse2.Xor(V0, V1);
            // Skip the last (i = lenV - 1) iteration of the streak-fixup output pass.
            // That iteration's write target ZZ[2L + 1] is past the reducer's window
            // (m_sizeExt covers ZZ[0..2L]); nothing else reads it after, so the
            // store + XOR would be dead.
            for (int i = 0; i < L; ++i)
            {
                ZZ[lenV + i] = Sse2.Xor(ZZ[i], W);
            }

            // Cross-product phase. lo < hi <= L; when hi == L, X_hi/Y_hi come from
            // the tail V128 instead of the X/Y span (lo stays < L throughout since
            // lo < hi).
            int doubleLast = L << 1;
            for (int zPos = 1; zPos < doubleLast; ++zPos)
            {
                int hi = System.Math.Min(L, zPos);
                int lo = zPos - hi;
                while (lo < hi)
                {
                    var X_hi = hi < L ? X[hi] : XL;
                    var Y_hi = hi < L ? Y[hi] : YL;
                    Mul2x2(Sse2.Xor(X[lo], X_hi), Sse2.Xor(Y[lo], Y_hi), out var W0, out var W1);
                    ZZ[zPos    ] = Sse2.Xor(ZZ[zPos    ], W0);
                    ZZ[zPos + 1] = Sse2.Xor(ZZ[zPos + 1], W1);
                    ++lo;
                    --hi;
                }
            }
        }
    }
}
#endif
