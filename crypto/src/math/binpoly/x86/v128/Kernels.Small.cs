#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Org.BouncyCastle.Math.BinPoly.X86.V128
{
    // Fixed-size CLMUL kernels (ImplMul1..ImplMul10) for small operand lengths. Each ImplMulN
    // is called by the matching per-size sealed impl (Size1..Size10), which the factory
    // Backend.CreateBinPolyMul selects by operand size; keeping every operand limb reachable
    // in registers lets the JIT fold offsets and skip the generic loop / blocking overhead an
    // arbitrary-degree kernel would need. CLMUL-only — the non-PCLMULQDQ scalar backend
    // handles every size through its own size-general Scalar.Kernels.ImplMul.
    internal static partial class Kernels
    {
        // Pack x[0] and y[0] into one vector and self-clmul (high * low) for the single 1x1
        // product.
        internal static void ImplMul1(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            var XY = Vector128.Create(x[0], y[0]);
            var P = Pclmulqdq.CarrylessMultiply(XY, XY, 0x01);
            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = P;
        }

        // Size 2: Karatsuba (3 PCLMULQDQ): A = x0*y0, B = x1*y1, C = (x0^x1)*(y0^y1), then
        // mid = A ^ B ^ C recovers the cross term x0*y1 + x1*y0 without a fourth multiply.
        // XsYs = (x0^x1, y0^y1) is derived via unpcklqdq/unpckhqdq + xor on X, Y so the whole
        // setup stays in SIMD pipes after the two vector loads. Factored into Mul2x2 so it can
        // be reused by Mul4x4 and ImplMul4 for the three sub-multiplies of their
        // 2+2 outer Karatsuba. Unlike Mul3x3 / Mul4x4 (scalar inputs), Mul2x2 takes packed
        // Vector128 inputs because 2 limbs = one vector and most callers already have the pack.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mul2x2(
            Vector128<ulong> X, Vector128<ulong> Y,
            out Vector128<ulong> W0, out Vector128<ulong> W1)
        {
            var XsYs = Sse2.Xor(Sse2.UnpackLow(X, Y), Sse2.UnpackHigh(X, Y));
            var A = Pclmulqdq.CarrylessMultiply(X, Y, 0x00);
            var B = Pclmulqdq.CarrylessMultiply(X, Y, 0x11);
            var C = Pclmulqdq.CarrylessMultiply(XsYs, XsYs, 0x01);
            var mid = Sse2.Xor(Sse2.Xor(A, B), C);
            W0 = Sse2.Xor(A, Sse2.ShiftLeftLogical128BitLane (mid, 8));
            W1 = Sse2.Xor(B, Sse2.ShiftRightLogical128BitLane(mid, 8));
        }

        internal static void ImplMul2(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            var X = Vector128.Create(x[0], x[1]);
            var Y = Vector128.Create(y[0], y[1]);
            Mul2x2(X, Y, out var W0, out var W1);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = W0;
            ZZ[1] = W1;
        }

        // Size 3: arbitrary-degree Karatsuba (6 PCLMULQDQ vs 9 schoolbook). Three diagonals
        // P_ii = x_i * y_i and three cross products Q_ij = (x_i ^ x_j) * (y_i ^ y_j); the
        // middle term M_ij = x_i*y_j + x_j*y_i is recovered as Q_ij ^ P_ii ^ P_jj. Output is
        // three Vector128 lanes (W0..W2) covering limbs 0..5. Factored into Mul3x3 so the
        // size-6 (3+3 Karatsuba) kernel can reuse it as a sub-multiply.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mul3x3(
            ulong x0, ulong x1, ulong x2,
            ulong y0, ulong y1, ulong y2,
            out Vector128<ulong> W0, out Vector128<ulong> W1, out Vector128<ulong> W2)
        {
            var X0Y0 = Vector128.Create(x0, y0);
            var X1Y1 = Vector128.Create(x1, y1);
            var X2Y2 = Vector128.Create(x2, y2);

            var P00 = Pclmulqdq.CarrylessMultiply(X0Y0, X0Y0, 0x01);
            var P11 = Pclmulqdq.CarrylessMultiply(X1Y1, X1Y1, 0x01);
            var P22 = Pclmulqdq.CarrylessMultiply(X2Y2, X2Y2, 0x01);

            var XY01 = Sse2.Xor(X0Y0, X1Y1);
            var XY02 = Sse2.Xor(X0Y0, X2Y2);
            var XY12 = Sse2.Xor(X1Y1, X2Y2);

            var Q01 = Pclmulqdq.CarrylessMultiply(XY01, XY01, 0x01);
            var Q02 = Pclmulqdq.CarrylessMultiply(XY02, XY02, 0x01);
            var Q12 = Pclmulqdq.CarrylessMultiply(XY12, XY12, 0x01);

            var M01 = Sse2.Xor(Sse2.Xor(Q01, P00), P11);
            var M02 = Sse2.Xor(Sse2.Xor(Q02, P00), P22);
            var M12 = Sse2.Xor(Sse2.Xor(Q12, P11), P22);

            W0 = Sse2.Xor(P00, Sse2.ShiftLeftLogical128BitLane (M01, 8));
            W1 = Sse2.Xor(
                Sse2.Xor(P11, Sse2.ShiftRightLogical128BitLane(M01, 8)),
                Sse2.Xor(M02, Sse2.ShiftLeftLogical128BitLane (M12, 8)));
            W2 = Sse2.Xor(P22, Sse2.ShiftRightLogical128BitLane(M12, 8));
        }

        internal static void ImplMul3(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            Mul3x3(x[0], x[1], x[2], y[0], y[1], y[2], out var W0, out var W1, out var W2);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = W0;
            ZZ[1] = W1;
            ZZ[2] = W2;
        }

        // Size-4 inner Karatsuba helper (2+2 split, 9 PCLMULQDQ): three Mul2x2
        // sub-multiplies for z0 = x_lo*y_lo, z2 = x_hi*y_hi, z_full_mid = (x_lo+x_hi)*
        // (y_lo+y_hi); z_mid = z_full_mid + z0 + z2. Output: W0 = z0_W0; W1 = z0_W1 +
        // z_mid_W0; W2 = z2_W0 + z_mid_W1; W3 = z2_W1. Used by ImplMul4 / ImplMul7 /
        // ImplMul8. The primary form takes packed Vector128
        // inputs so a hot caller can hoist X_lo / X_hi across an inner sweep without
        // re-packing; the scalar-input overload below is a packing wrapper for the
        // size-N kernels.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mul4x4(
            Vector128<ulong> Xlo, Vector128<ulong> Xhi,
            Vector128<ulong> Ylo, Vector128<ulong> Yhi,
            out Vector128<ulong> W0, out Vector128<ulong> W1,
            out Vector128<ulong> W2, out Vector128<ulong> W3)
        {
            var Xsum = Sse2.Xor(Xlo, Xhi);
            var Ysum = Sse2.Xor(Ylo, Yhi);

            Mul2x2(Xlo, Ylo, out var Z0W0, out var Z0W1);
            Mul2x2(Xhi, Yhi, out var Z2W0, out var Z2W1);
            Mul2x2(Xsum, Ysum, out var ZMW0, out var ZMW1);

            var ZmidW0 = Sse2.Xor(Sse2.Xor(ZMW0, Z0W0), Z2W0);
            var ZmidW1 = Sse2.Xor(Sse2.Xor(ZMW1, Z0W1), Z2W1);

            W0 = Z0W0;
            W1 = Sse2.Xor(Z0W1, ZmidW0);
            W2 = Sse2.Xor(Z2W0, ZmidW1);
            W3 = Z2W1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mul4x4(
            ulong x0, ulong x1, ulong x2, ulong x3,
            ulong y0, ulong y1, ulong y2, ulong y3,
            out Vector128<ulong> W0, out Vector128<ulong> W1,
            out Vector128<ulong> W2, out Vector128<ulong> W3)
        {
            Mul4x4(
                Vector128.Create(x0, x1), Vector128.Create(x2, x3),
                Vector128.Create(y0, y1), Vector128.Create(y2, y3),
                out W0, out W1, out W2, out W3);
        }

        // Size 4: outer 2+2 Karatsuba via Mul4x4.
        internal static void ImplMul4(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            Mul4x4(x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3],
                out var W0, out var W1, out var W2, out var W3);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = W0;
            ZZ[1] = W1;
            ZZ[2] = W2;
            ZZ[3] = W3;
        }

        // Size 5: arbitrary-degree Karatsuba (5 diagonals + 10 cross sums = 15 PCLMULQDQ vs
        // 25 schoolbook). Mirrors Mul3x3's structure with a wider middle: at output position
        // p, contributions come from each M_ij where i+j is p or p-1. Output is 5 Vector128
        // lanes W0..W4 covering limbs 0..9. Factored into Mul5x5 so the size-N kernels
        // (ImplMul5 / ImplMul10, including the size-10 schoolbook 5+5 decomposition) can
        // reuse it as a sub-multiply.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mul5x5(
            ulong x0, ulong x1, ulong x2, ulong x3, ulong x4,
            ulong y0, ulong y1, ulong y2, ulong y3, ulong y4,
            out Vector128<ulong> W0, out Vector128<ulong> W1, out Vector128<ulong> W2,
            out Vector128<ulong> W3, out Vector128<ulong> W4)
        {
            var X0Y0 = Vector128.Create(x0, y0);
            var X1Y1 = Vector128.Create(x1, y1);
            var X2Y2 = Vector128.Create(x2, y2);
            var X3Y3 = Vector128.Create(x3, y3);
            var X4Y4 = Vector128.Create(x4, y4);

            var P00 = Pclmulqdq.CarrylessMultiply(X0Y0, X0Y0, 0x01);
            var P11 = Pclmulqdq.CarrylessMultiply(X1Y1, X1Y1, 0x01);
            var P22 = Pclmulqdq.CarrylessMultiply(X2Y2, X2Y2, 0x01);
            var P33 = Pclmulqdq.CarrylessMultiply(X3Y3, X3Y3, 0x01);
            var P44 = Pclmulqdq.CarrylessMultiply(X4Y4, X4Y4, 0x01);

            var XY01 = Sse2.Xor(X0Y0, X1Y1);
            var XY02 = Sse2.Xor(X0Y0, X2Y2);
            var XY03 = Sse2.Xor(X0Y0, X3Y3);
            var XY04 = Sse2.Xor(X0Y0, X4Y4);
            var XY12 = Sse2.Xor(X1Y1, X2Y2);
            var XY13 = Sse2.Xor(X1Y1, X3Y3);
            var XY14 = Sse2.Xor(X1Y1, X4Y4);
            var XY23 = Sse2.Xor(X2Y2, X3Y3);
            var XY24 = Sse2.Xor(X2Y2, X4Y4);
            var XY34 = Sse2.Xor(X3Y3, X4Y4);

            var Q01 = Pclmulqdq.CarrylessMultiply(XY01, XY01, 0x01);
            var Q02 = Pclmulqdq.CarrylessMultiply(XY02, XY02, 0x01);
            var Q03 = Pclmulqdq.CarrylessMultiply(XY03, XY03, 0x01);
            var Q04 = Pclmulqdq.CarrylessMultiply(XY04, XY04, 0x01);
            var Q12 = Pclmulqdq.CarrylessMultiply(XY12, XY12, 0x01);
            var Q13 = Pclmulqdq.CarrylessMultiply(XY13, XY13, 0x01);
            var Q14 = Pclmulqdq.CarrylessMultiply(XY14, XY14, 0x01);
            var Q23 = Pclmulqdq.CarrylessMultiply(XY23, XY23, 0x01);
            var Q24 = Pclmulqdq.CarrylessMultiply(XY24, XY24, 0x01);
            var Q34 = Pclmulqdq.CarrylessMultiply(XY34, XY34, 0x01);

            var M01 = Sse2.Xor(Sse2.Xor(Q01, P00), P11);
            var M02 = Sse2.Xor(Sse2.Xor(Q02, P00), P22);
            var M03 = Sse2.Xor(Sse2.Xor(Q03, P00), P33);
            var M04 = Sse2.Xor(Sse2.Xor(Q04, P00), P44);
            var M12 = Sse2.Xor(Sse2.Xor(Q12, P11), P22);
            var M13 = Sse2.Xor(Sse2.Xor(Q13, P11), P33);
            var M14 = Sse2.Xor(Sse2.Xor(Q14, P11), P44);
            var M23 = Sse2.Xor(Sse2.Xor(Q23, P22), P33);
            var M24 = Sse2.Xor(Sse2.Xor(Q24, P22), P44);
            var M34 = Sse2.Xor(Sse2.Xor(Q34, P33), P44);

            // Fold cross-terms that share a position (i+j matches): position 3 has M03 and M12;
            // position 4 has M04 and M13; position 5 has M14 and M23.
            var M03_12 = Sse2.Xor(M03, M12);
            var M04_13 = Sse2.Xor(M04, M13);
            var M14_23 = Sse2.Xor(M14, M23);

            W0 = Sse2.Xor(P00, Sse2.ShiftLeftLogical128BitLane (M01, 8));
            W1 = Sse2.Xor(
                Sse2.Xor(P11, Sse2.ShiftRightLogical128BitLane(M01, 8)),
                Sse2.Xor(M02, Sse2.ShiftLeftLogical128BitLane (M03_12, 8)));
            W2 = Sse2.Xor(
                Sse2.Xor(P22, Sse2.ShiftRightLogical128BitLane(M03_12, 8)),
                Sse2.Xor(M04_13, Sse2.ShiftLeftLogical128BitLane (M14_23, 8)));
            W3 = Sse2.Xor(
                Sse2.Xor(P33, Sse2.ShiftRightLogical128BitLane(M14_23, 8)),
                Sse2.Xor(M24, Sse2.ShiftLeftLogical128BitLane (M34, 8)));
            W4 = Sse2.Xor(P44, Sse2.ShiftRightLogical128BitLane(M34, 8));
        }

        internal static void ImplMul5(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            Mul5x5(x[0], x[1], x[2], x[3], x[4], y[0], y[1], y[2], y[3], y[4],
                out var W0, out var W1, out var W2, out var W3, out var W4);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = W0;
            ZZ[1] = W1;
            ZZ[2] = W2;
            ZZ[3] = W3;
            ZZ[4] = W4;
        }

        // Size 6: outer 3+3 Karatsuba. Three size-3 sub-multiplies via Mul3x3 (18 PCLMULQDQ
        // total: 6 each, vs 36 schoolbook). z_mid = z_full_mid + z0 + z2 with the three
        // size-3 products. Output is 6 Vector128 lanes; the middle lanes splice z_mid into
        // z0 and z2 via 64-bit lane shifts.
        internal static void ImplMul6(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            ulong xs0 = x[0] ^ x[3];
            ulong xs1 = x[1] ^ x[4];
            ulong xs2 = x[2] ^ x[5];
            ulong ys0 = y[0] ^ y[3];
            ulong ys1 = y[1] ^ y[4];
            ulong ys2 = y[2] ^ y[5];

            Mul3x3(x[0], x[1], x[2], y[0], y[1], y[2],
                out var Z0W0, out var Z0W1, out var Z0W2);
            Mul3x3(x[3], x[4], x[5], y[3], y[4], y[5],
                out var Z2W0, out var Z2W1, out var Z2W2);
            Mul3x3(xs0, xs1, xs2, ys0, ys1, ys2,
                out var ZMW0, out var ZMW1, out var ZMW2);

            var ZmidW0 = Sse2.Xor(Sse2.Xor(ZMW0, Z0W0), Z2W0);
            var ZmidW1 = Sse2.Xor(Sse2.Xor(ZMW1, Z0W1), Z2W1);
            var ZmidW2 = Sse2.Xor(Sse2.Xor(ZMW2, Z0W2), Z2W2);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = Z0W0;
            ZZ[1] = Sse2.Xor(Z0W1, Sse2.ShiftLeftLogical128BitLane(ZmidW0, 8));
            ZZ[2] = Sse2.Xor(
                Sse2.Xor(Z0W2, Sse2.ShiftRightLogical128BitLane(ZmidW0, 8)),
                Sse2.ShiftLeftLogical128BitLane (ZmidW1, 8));
            ZZ[3] = Sse2.Xor(
                Sse2.Xor(Z2W0, Sse2.ShiftRightLogical128BitLane(ZmidW1, 8)),
                Sse2.ShiftLeftLogical128BitLane (ZmidW2, 8));
            ZZ[4] = Sse2.Xor(Z2W1, Sse2.ShiftRightLogical128BitLane(ZmidW2, 8));
            ZZ[5] = Z2W2;
        }

        // Size 7: outer 4+3 Karatsuba (24 PCLMULQDQ vs 49 schoolbook). z0 = x_lo(4) *
        // y_lo(4) via Mul4x4 (9 PCLMULQDQ), z2 = x_hi(3) * y_hi(3) via Mul3x3 (6 PCLMULQDQ),
        // z_full_mid = (x_lo + x_hi_pad) * (y_lo + y_hi_pad) via Mul4x4 (9 PCLMULQDQ). The
        // x_hi_pad / y_hi_pad have a zero top limb so the size-4 sum lookup just takes
        // x_lo[3] / y_lo[3] for that slot. Output W3 of z_mid has limb 7 = 0 (consistency).
        // Factored into Mul7x7 so ImplMul7 can reuse it as a sub-multiply.
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mul7x7(
            ulong x0, ulong x1, ulong x2, ulong x3, ulong x4, ulong x5, ulong x6,
            ulong y0, ulong y1, ulong y2, ulong y3, ulong y4, ulong y5, ulong y6,
            out Vector128<ulong> W0, out Vector128<ulong> W1, out Vector128<ulong> W2,
            out Vector128<ulong> W3, out Vector128<ulong> W4, out Vector128<ulong> W5,
            out Vector128<ulong> W6)
        {
            ulong xs0 = x0 ^ x4;
            ulong xs1 = x1 ^ x5;
            ulong xs2 = x2 ^ x6;
            ulong xs3 = x3;
            ulong ys0 = y0 ^ y4;
            ulong ys1 = y1 ^ y5;
            ulong ys2 = y2 ^ y6;
            ulong ys3 = y3;

            Mul4x4(x0, x1, x2, x3, y0, y1, y2, y3,
                out var Z0W0, out var Z0W1, out var Z0W2, out var Z0W3);
            Mul4x4(xs0, xs1, xs2, xs3, ys0, ys1, ys2, ys3,
                out var ZMW0, out var ZMW1, out var ZMW2, out var ZMW3);

            Mul3x3(x4, x5, x6, y4, y5, y6,
                out var Z2W0, out var Z2W1, out var Z2W2);

            var ZmidW0 = Sse2.Xor(Sse2.Xor(ZMW0, Z0W0), Z2W0);
            var ZmidW1 = Sse2.Xor(Sse2.Xor(ZMW1, Z0W1), Z2W1);
            var ZmidW2 = Sse2.Xor(Sse2.Xor(ZMW2, Z0W2), Z2W2);
            var ZmidW3 = Sse2.Xor(ZMW3, Z0W3);

            W0 = Z0W0;
            W1 = Z0W1;
            W2 = Sse2.Xor(Z0W2, ZmidW0);
            W3 = Sse2.Xor(Z0W3, ZmidW1);
            W4 = Sse2.Xor(ZmidW2, Z2W0);
            W5 = Sse2.Xor(ZmidW3, Z2W1);
            W6 = Z2W2;
        }

        internal static void ImplMul7(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            Mul7x7(x[0], x[1], x[2], x[3], x[4], x[5], x[6],
                y[0], y[1], y[2], y[3], y[4], y[5], y[6],
                out var W0, out var W1, out var W2, out var W3, out var W4, out var W5,
                out var W6);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = W0;
            ZZ[1] = W1;
            ZZ[2] = W2;
            ZZ[3] = W3;
            ZZ[4] = W4;
            ZZ[5] = W5;
            ZZ[6] = W6;
        }

        // Size 8: outer 4+4 Karatsuba (clean recursive descent into 2+2). Three size-4
        // sub-multiplies via Mul4x4 (9 PCLMULQDQ each, 27 total) vs 64 schoolbook. The output
        // layout mirrors size 4's, scaled 2x.
        internal static void ImplMul8(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            ulong xs0 = x[0] ^ x[4];
            ulong xs1 = x[1] ^ x[5];
            ulong xs2 = x[2] ^ x[6];
            ulong xs3 = x[3] ^ x[7];
            ulong ys0 = y[0] ^ y[4];
            ulong ys1 = y[1] ^ y[5];
            ulong ys2 = y[2] ^ y[6];
            ulong ys3 = y[3] ^ y[7];

            Mul4x4(x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3],
                out var Z0W0, out var Z0W1, out var Z0W2, out var Z0W3);
            Mul4x4(x[4], x[5], x[6], x[7], y[4], y[5], y[6], y[7],
                out var Z2W0, out var Z2W1, out var Z2W2, out var Z2W3);
            Mul4x4(xs0, xs1, xs2, xs3, ys0, ys1, ys2, ys3,
                out var ZMW0, out var ZMW1, out var ZMW2, out var ZMW3);

            var ZmidW0 = Sse2.Xor(Sse2.Xor(ZMW0, Z0W0), Z2W0);
            var ZmidW1 = Sse2.Xor(Sse2.Xor(ZMW1, Z0W1), Z2W1);
            var ZmidW2 = Sse2.Xor(Sse2.Xor(ZMW2, Z0W2), Z2W2);
            var ZmidW3 = Sse2.Xor(Sse2.Xor(ZMW3, Z0W3), Z2W3);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = Z0W0;
            ZZ[1] = Z0W1;
            ZZ[2] = Sse2.Xor(Z0W2, ZmidW0);
            ZZ[3] = Sse2.Xor(Z0W3, ZmidW1);
            ZZ[4] = Sse2.Xor(ZmidW2, Z2W0);
            ZZ[5] = Sse2.Xor(ZmidW3, Z2W1);
            ZZ[6] = Z2W2;
            ZZ[7] = Z2W3;
        }

        // Size 9: outer 3-way Karatsuba over 3-limb blocks. Six size-3 sub-multiplies via
        // Mul3x3: three diagonals P_ii = x_i*y_i and three cross sums Q_ij = (x_i+x_j) *
        // (y_i+y_j); recover M_ij = Q_ij ^ P_ii ^ P_jj. 36 PCLMULQDQ total vs 81 schoolbook.
        // Combination is denser than other sizes because each 6-limb sub-product (P or M)
        // straddles four 2-limb W lanes when its block position is odd.
        internal static void ImplMul9(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            ulong xs01_0 = x[0] ^ x[3]; ulong xs01_1 = x[1] ^ x[4]; ulong xs01_2 = x[2] ^ x[5];
            ulong xs02_0 = x[0] ^ x[6]; ulong xs02_1 = x[1] ^ x[7]; ulong xs02_2 = x[2] ^ x[8];
            ulong xs12_0 = x[3] ^ x[6]; ulong xs12_1 = x[4] ^ x[7]; ulong xs12_2 = x[5] ^ x[8];
            ulong ys01_0 = y[0] ^ y[3]; ulong ys01_1 = y[1] ^ y[4]; ulong ys01_2 = y[2] ^ y[5];
            ulong ys02_0 = y[0] ^ y[6]; ulong ys02_1 = y[1] ^ y[7]; ulong ys02_2 = y[2] ^ y[8];
            ulong ys12_0 = y[3] ^ y[6]; ulong ys12_1 = y[4] ^ y[7]; ulong ys12_2 = y[5] ^ y[8];

            Mul3x3(x[0], x[1], x[2], y[0], y[1], y[2],
                out var P00W0, out var P00W1, out var P00W2);
            Mul3x3(x[3], x[4], x[5], y[3], y[4], y[5],
                out var P11W0, out var P11W1, out var P11W2);
            Mul3x3(x[6], x[7], x[8], y[6], y[7], y[8],
                out var P22W0, out var P22W1, out var P22W2);
            Mul3x3(xs01_0, xs01_1, xs01_2, ys01_0, ys01_1, ys01_2,
                out var Q01W0, out var Q01W1, out var Q01W2);
            Mul3x3(xs02_0, xs02_1, xs02_2, ys02_0, ys02_1, ys02_2,
                out var Q02W0, out var Q02W1, out var Q02W2);
            Mul3x3(xs12_0, xs12_1, xs12_2, ys12_0, ys12_1, ys12_2,
                out var Q12W0, out var Q12W1, out var Q12W2);

            var M01W0 = Sse2.Xor(Sse2.Xor(Q01W0, P00W0), P11W0);
            var M01W1 = Sse2.Xor(Sse2.Xor(Q01W1, P00W1), P11W1);
            var M01W2 = Sse2.Xor(Sse2.Xor(Q01W2, P00W2), P11W2);
            var M02W0 = Sse2.Xor(Sse2.Xor(Q02W0, P00W0), P22W0);
            var M02W1 = Sse2.Xor(Sse2.Xor(Q02W1, P00W1), P22W1);
            var M02W2 = Sse2.Xor(Sse2.Xor(Q02W2, P00W2), P22W2);
            var M12W0 = Sse2.Xor(Sse2.Xor(Q12W0, P11W0), P22W0);
            var M12W1 = Sse2.Xor(Sse2.Xor(Q12W1, P11W1), P22W1);
            var M12W2 = Sse2.Xor(Sse2.Xor(Q12W2, P11W2), P22W2);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = P00W0;
            ZZ[1] = Sse2.Xor(P00W1, Sse2.ShiftLeftLogical128BitLane(M01W0, 8));
            ZZ[2] = Sse2.Xor(Sse2.Xor(P00W2, Sse2.ShiftRightLogical128BitLane(M01W0, 8)),
                Sse2.ShiftLeftLogical128BitLane (M01W1, 8));
            ZZ[3] = Sse2.Xor(Sse2.Xor(P11W0, M02W0),
                Sse2.Xor(Sse2.ShiftRightLogical128BitLane(M01W1, 8),
                         Sse2.ShiftLeftLogical128BitLane (M01W2, 8)));
            ZZ[4] = Sse2.Xor(Sse2.Xor(P11W1, M02W1),
                Sse2.Xor(Sse2.ShiftRightLogical128BitLane(M01W2, 8),
                         Sse2.ShiftLeftLogical128BitLane (M12W0, 8)));
            ZZ[5] = Sse2.Xor(Sse2.Xor(P11W2, M02W2),
                Sse2.Xor(Sse2.ShiftRightLogical128BitLane(M12W0, 8),
                         Sse2.ShiftLeftLogical128BitLane (M12W1, 8)));
            ZZ[6] = Sse2.Xor(P22W0,
                Sse2.Xor(Sse2.ShiftRightLogical128BitLane(M12W1, 8),
                         Sse2.ShiftLeftLogical128BitLane (M12W2, 8)));
            ZZ[7] = Sse2.Xor(P22W1, Sse2.ShiftRightLogical128BitLane(M12W2, 8));
            ZZ[8] = P22W2;
        }

        // Size 10: outer 5+5 schoolbook with 4 Mul5x5 sub-multiplies (60 PCLMULQDQ vs
        // 100 schoolbook). z = A + B*X^5 + C*X^5 + D*X^10 where A = x_lo*y_lo,
        // D = x_hi*y_hi, B = x_lo*y_hi, C = x_hi*y_lo (each a 10-limb sub-product over
        // 5 input limbs). A overwrites zz[0..9] and D overwrites zz[10..19]; B and C
        // are then XORed into the unaligned 10-limb window zz[5..14] which already
        // holds A's high half and D's low half. Chosen over the 5+5 outer Karatsuba
        // (3 sub-mults, 45 PCLMULQDQ) to keep the data flow flat — Karatsuba would
        // save 15 PCLMULQDQ but add ~20 XORs (sums + recombination) at this size.
        internal static void ImplMul10(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> zz)
        {
            // A = x_lo * y_lo  -> overwrite zz[0..9]
            Mul5x5(x[0], x[1], x[2], x[3], x[4], y[0], y[1], y[2], y[3], y[4],
                out var A0, out var A1, out var A2, out var A3, out var A4);

            // D = x_hi * y_hi  -> overwrite zz[10..19]
            Mul5x5(x[5], x[6], x[7], x[8], x[9], y[5], y[6], y[7], y[8], y[9],
                out var D0, out var D1, out var D2, out var D3, out var D4);

            // B = x_lo * y_hi and C = x_hi * y_lo. Folded together via XOR and applied
            // to zz[5..14] in one pass so each lane only takes one load-modify-store.
            Mul5x5(x[0], x[1], x[2], x[3], x[4], y[5], y[6], y[7], y[8], y[9],
                out var B0, out var B1, out var B2, out var B3, out var B4);
            Mul5x5(x[5], x[6], x[7], x[8], x[9], y[0], y[1], y[2], y[3], y[4],
                out var C0, out var C1, out var C2, out var C3, out var C4);

            var ZZ = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz);
            ZZ[0] = A0;
            ZZ[1] = A1;
            ZZ[2] = A2;
            ZZ[3] = A3;
            ZZ[4] = A4;
            ZZ[5] = D0;
            ZZ[6] = D1;
            ZZ[7] = D2;
            ZZ[8] = D3;
            ZZ[9] = D4;

            // Unaligned Vector128 view starting at zz[5]; XOR (B ^ C) into zz[5..14].
            var ZZmid = MemoryMarshal.Cast<ulong, Vector128<ulong>>(zz[5..]);
            ZZmid[0] = Sse2.Xor(ZZmid[0], Sse2.Xor(B0, C0));
            ZZmid[1] = Sse2.Xor(ZZmid[1], Sse2.Xor(B1, C1));
            ZZmid[2] = Sse2.Xor(ZZmid[2], Sse2.Xor(B2, C2));
            ZZmid[3] = Sse2.Xor(ZZmid[3], Sse2.Xor(B3, C3));
            ZZmid[4] = Sse2.Xor(ZZmid[4], Sse2.Xor(B4, C4));
        }
    }
}
#endif
