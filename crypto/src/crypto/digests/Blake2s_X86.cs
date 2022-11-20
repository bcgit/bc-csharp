#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Org.BouncyCastle.Crypto.Digests
{
    // License from the original code created by Clinton Ingram (saucecontrol) for Blake2Fast 
    // at https://github.com/saucecontrol/Blake2Fast. The code has been copied and modified.

    // The MIT License

    // Copyright(c) 2018-2021 Clinton Ingram

    // Permission is hereby granted, free of charge, to any person obtaining a copy
    // of this software and associated documentation files (the "Software"), to deal
    // in the Software without restriction, including without limitation the rights
    // to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    // copies of the Software, and to permit persons to whom the Software is
    // furnished to do so, subject to the following conditions:

    // The above copyright notice and this permission notice shall be included in
    // all copies or substantial portions of the Software.

    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    // THE SOFTWARE.

    internal static class Blake2s_X86
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Compress(bool isFinal, Span<uint> hashBuffer, ReadOnlySpan<byte> message, uint totalSegmentsLow, uint totalSegmentsHigh, ReadOnlySpan<uint> blakeIV)
        {
            if (!Sse41.IsSupported || !BitConverter.IsLittleEndian)
                throw new PlatformNotSupportedException(nameof(Blake2s_X86));

            Debug.Assert(message.Length >= Unsafe.SizeOf<uint>() * 8);
            Debug.Assert(hashBuffer.Length >= 8);

            Vector128<byte> r8 = Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
            Vector128<byte> r16 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

            var hashBytes = MemoryMarshal.AsBytes(hashBuffer);
            var ivBytes = MemoryMarshal.AsBytes(blakeIV);

            var r_14 = isFinal ? uint.MaxValue : 0;
            var t_0 = Vector128.Create(totalSegmentsLow, totalSegmentsHigh, r_14, 0);

            Vector128<uint> row1 = LoadVector128<uint>(hashBytes);
            Vector128<uint> row2 = LoadVector128<uint>(hashBytes[Vector128<byte>.Count..]);
            Vector128<uint> row3 = LoadVector128<uint>(ivBytes);
            Vector128<uint> row4 = LoadVector128<uint>(ivBytes[Vector128<byte>.Count..]);
            row4 = Sse2.Xor(row4, t_0);

            Vector128<uint> orig_1 = row1;
            Vector128<uint> orig_2 = row2;

            Perform10Rounds(r8, r16, message, ref row1, ref row2, ref row3, ref row4);

            row1 = Sse2.Xor(row1, row3);
            row2 = Sse2.Xor(row2, row4);
            row1 = Sse2.Xor(row1, orig_1);
            row2 = Sse2.Xor(row2, orig_2);

            Store(row1, hashBytes);
            Store(row2, hashBytes[Vector128<byte>.Count..]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Perform10Rounds(Vector128<byte> r8, Vector128<byte> r16, ReadOnlySpan<byte> m, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, ref Vector128<uint> row4)
        {
            Debug.Assert(m.Length >= Unsafe.SizeOf<uint>() * 16);

            #region Rounds
            var m0 = LoadVector128<uint>(m);
            var m1 = LoadVector128<uint>(m[Vector128<byte>.Count..]);
            var m2 = LoadVector128<uint>(m[(Vector128<byte>.Count * 2)..]);
            var m3 = LoadVector128<uint>(m[(Vector128<byte>.Count * 3)..]);

            //ROUND 1
            var b0 = Sse.Shuffle(m0.AsSingle(), m1.AsSingle(), 0b_10_00_10_00).AsUInt32();

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            b0 = Sse.Shuffle(m0.AsSingle(), m1.AsSingle(), 0b_11_01_11_01).AsUInt32();

            //G2
            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            var t0 = Sse2.Shuffle(m2, 0b_11_10_00_01);
            var t1 = Sse2.Shuffle(m3, 0b_00_01_11_10);
            b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_11_00_00_11).AsUInt32();

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_11_11_00).AsUInt32();
            b0 = Sse2.Shuffle(t0, 0b_10_11_00_01);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 2
            t0 = Sse41.Blend(m1.AsUInt16(), m2.AsUInt16(), 0b_00_00_11_00).AsUInt32();
            t1 = Sse2.ShiftLeftLogical128BitLane(m3, 4);
            var t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_11_11_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_01_00_11);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.Shuffle(m2, 0b_00_00_10_00);
            t1 = Sse41.Blend(m1.AsUInt16(), m3.AsUInt16(), 0b_11_00_00_00).AsUInt32();
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_11_11_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_11_00_01);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse2.ShiftLeftLogical128BitLane(m1, 4);
            t1 = Sse41.Blend(m2.AsUInt16(), t0.AsUInt16(), 0b_00_11_00_00).AsUInt32();
            t2 = Sse41.Blend(m0.AsUInt16(), t1.AsUInt16(), 0b_11_11_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_11_00_01_10);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.UnpackHigh(m0, m1);
            t1 = Sse2.ShiftLeftLogical128BitLane(m3, 4);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_11_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_11_00_01_10);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 3
            t0 = Sse2.UnpackHigh(m2, m3);
            t1 = Sse41.Blend(m3.AsUInt16(), m1.AsUInt16(), 0b_00_00_11_00).AsUInt32();
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_11_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_11_01_00_10);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.UnpackLow(m2, m0);
            t1 = Sse41.Blend(t0.AsUInt16(), m0.AsUInt16(), 0b_11_11_00_00).AsUInt32();
            t2 = Sse2.ShiftLeftLogical128BitLane(m3, 8);
            b0 = Sse41.Blend(t1.AsUInt16(), t2.AsUInt16(), 0b_11_00_00_00).AsUInt32();

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse41.Blend(m0.AsUInt16(), m2.AsUInt16(), 0b_00_11_11_00).AsUInt32();
            t1 = Sse2.ShiftRightLogical128BitLane(m1, 12);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_00_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_00_11_10_01);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.ShiftLeftLogical128BitLane(m3, 4);
            t1 = Sse41.Blend(m0.AsUInt16(), m1.AsUInt16(), 0b_00_11_00_11).AsUInt32();
            t2 = Sse41.Blend(t1.AsUInt16(), t0.AsUInt16(), 0b_11_00_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_01_10_11_00);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 4
            t0 = Sse2.UnpackHigh(m0, m1);
            t1 = Sse2.UnpackHigh(t0, m2);
            t2 = Sse41.Blend(t1.AsUInt16(), m3.AsUInt16(), 0b_00_00_11_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_11_01_00_10);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.ShiftLeftLogical128BitLane(m2, 8);
            t1 = Sse41.Blend(m3.AsUInt16(), m0.AsUInt16(), 0b_00_00_11_00).AsUInt32();
            t2 = Sse41.Blend(t1.AsUInt16(), t0.AsUInt16(), 0b_11_00_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_00_01_11);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse41.Blend(m0.AsUInt16(), m1.AsUInt16(), 0b_00_00_11_11).AsUInt32();
            t1 = Sse41.Blend(t0.AsUInt16(), m3.AsUInt16(), 0b_11_00_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t1, 0b_00_01_10_11);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Ssse3.AlignRight(m0, m1, 4);
            b0 = Sse41.Blend(t0.AsUInt16(), m2.AsUInt16(), 0b_00_11_00_11).AsUInt32();

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 5
            t0 = Sse2.UnpackLow(m1.AsUInt64(), m2.AsUInt64()).AsUInt32();
            t1 = Sse2.UnpackHigh(m0.AsUInt64(), m2.AsUInt64()).AsUInt32();
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_11_00_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_00_01_11);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.UnpackHigh(m1.AsUInt64(), m3.AsUInt64()).AsUInt32();
            t1 = Sse2.UnpackLow(m0.AsUInt64(), m1.AsUInt64()).AsUInt32();
            b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_11_00_11).AsUInt32();

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse2.UnpackHigh(m3.AsUInt64(), m1.AsUInt64()).AsUInt32();
            t1 = Sse2.UnpackHigh(m2.AsUInt64(), m0.AsUInt64()).AsUInt32();
            t2 = Sse41.Blend(t1.AsUInt16(), t0.AsUInt16(), 0b_00_11_00_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_01_00_11);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse41.Blend(m0.AsUInt16(), m2.AsUInt16(), 0b_00_00_00_11).AsUInt32();
            t1 = Sse2.ShiftLeftLogical128BitLane(t0, 8);
            t2 = Sse41.Blend(t1.AsUInt16(), m3.AsUInt16(), 0b_00_00_11_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_00_11_01);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 6
            t0 = Sse2.UnpackHigh(m0, m1);
            t1 = Sse2.UnpackLow(m0, m2);
            b0 = Sse2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.ShiftRightLogical128BitLane(m2, 4);
            t1 = Sse41.Blend(m0.AsUInt16(), m3.AsUInt16(), 0b_00_00_00_11).AsUInt32();
            b0 = Sse41.Blend(t1.AsUInt16(), t0.AsUInt16(), 0b_00_11_11_00).AsUInt32();

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse41.Blend(m1.AsUInt16(), m0.AsUInt16(), 0b_00_00_11_00).AsUInt32();
            t1 = Sse2.ShiftRightLogical128BitLane(m3, 4);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_11_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_11_00_01);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.UnpackLow(m2.AsUInt64(), m1.AsUInt64()).AsUInt32();
            t1 = Sse2.Shuffle(m3, 0b_10_00_01_00);
            t2 = Sse2.ShiftRightLogical128BitLane(t0, 4);
            b0 = Sse41.Blend(t1.AsUInt16(), t2.AsUInt16(), 0b_00_11_00_11).AsUInt32();

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 7
            t0 = Sse2.ShiftLeftLogical128BitLane(m1, 12);
            t1 = Sse41.Blend(m0.AsUInt16(), m3.AsUInt16(), 0b_00_11_00_11).AsUInt32();
            b0 = Sse41.Blend(t1.AsUInt16(), t0.AsUInt16(), 0b_11_00_00_00).AsUInt32();

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse41.Blend(m3.AsUInt16(), m2.AsUInt16(), 0b_00_11_00_00).AsUInt32();
            t1 = Sse2.ShiftRightLogical128BitLane(m1, 4);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_00_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_01_11_00);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse2.UnpackLow(m0.AsUInt64(), m2.AsUInt64()).AsUInt32();
            t1 = Sse2.ShiftRightLogical128BitLane(m1, 4);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_11_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_11_01_00_10);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.UnpackHigh(m1, m2);
            t1 = Sse2.UnpackHigh(m0.AsUInt64(), t0.AsUInt64()).AsUInt32();
            b0 = Sse2.Shuffle(t1, 0b_00_01_10_11);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 8
            t0 = Sse2.UnpackHigh(m0, m1);
            t1 = Sse41.Blend(t0.AsUInt16(), m3.AsUInt16(), 0b_00_00_11_11).AsUInt32();
            b0 = Sse2.Shuffle(t1, 0b_10_00_11_01);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse41.Blend(m2.AsUInt16(), m3.AsUInt16(), 0b_00_11_00_00).AsUInt32();
            t1 = Sse2.ShiftRightLogical128BitLane(m0, 4);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_00_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_01_00_10_11);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse2.UnpackHigh(m0.AsUInt64(), m3.AsUInt64()).AsUInt32();
            t1 = Sse2.UnpackLow(m1.AsUInt64(), m2.AsUInt64()).AsUInt32();
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_11_11_00).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_11_01_00);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.UnpackLow(m0, m1);
            t1 = Sse2.UnpackHigh(m1, m2);
            t2 = Sse2.UnpackLow(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_10_01_00_11);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 9
            t0 = Sse2.UnpackHigh(m1, m3);
            t1 = Sse2.UnpackLow(t0.AsUInt64(), m0.AsUInt64()).AsUInt32();
            t2 = Sse41.Blend(t1.AsUInt16(), m2.AsUInt16(), 0b_11_00_00_00).AsUInt32();
            b0 = Sse2.ShuffleHigh(t2.AsUInt16(), 0b_01_00_11_10).AsUInt32();

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.UnpackHigh(m0, m3);
            t1 = Sse41.Blend(m2.AsUInt16(), t0.AsUInt16(), 0b_11_11_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t1, 0b_00_10_01_11);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse2.UnpackLow(m0.AsUInt64(), m3.AsUInt64()).AsUInt32();
            t1 = Sse2.ShiftRightLogical128BitLane(m2, 8);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_00_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_01_11_10_00);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse41.Blend(m1.AsUInt16(), m0.AsUInt16(), 0b_00_11_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t0, 0b_00_11_10_01);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);

            //ROUND 10
            t0 = Sse41.Blend(m0.AsUInt16(), m2.AsUInt16(), 0b_00_00_00_11).AsUInt32();
            t1 = Sse41.Blend(m1.AsUInt16(), m2.AsUInt16(), 0b_00_11_00_00).AsUInt32();
            t2 = Sse41.Blend(t1.AsUInt16(), t0.AsUInt16(), 0b_00_00_11_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_01_11_00_10);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse2.ShiftLeftLogical128BitLane(m0, 4);
            t1 = Sse41.Blend(m1.AsUInt16(), t0.AsUInt16(), 0b_11_00_00_00).AsUInt32();
            b0 = Sse2.Shuffle(t1, 0b_01_10_00_11);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Diagonalize(ref row1, ref row3, ref row4);

            t0 = Sse2.UnpackHigh(m0, m3);
            t1 = Sse2.UnpackLow(m2, m3);
            t2 = Sse2.UnpackHigh(t0.AsUInt64(), t1.AsUInt64()).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_00_10_01_11);

            G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

            t0 = Sse41.Blend(m3.AsUInt16(), m2.AsUInt16(), 0b_11_00_00_00).AsUInt32();
            t1 = Sse2.UnpackLow(m0, m3);
            t2 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_00_00_11_11).AsUInt32();
            b0 = Sse2.Shuffle(t2, 0b_01_10_11_00);

            G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

            Undiagonalize(ref row1, ref row3, ref row4);
            #endregion
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Diagonalize(ref Vector128<uint> row1, ref Vector128<uint> row3, ref Vector128<uint> row4)
        {
            //     +-------------------+        +-------------------+
            //     |  0 |  1 |  2 |  3 |        |  3 |  0 |  1 |  2 |
            //     +-------------------+        +-------------------+
            //     |  8 |  9 | 10 | 11 |  --->  |  9 | 10 | 11 |  8 |
            //     +-------------------+        +-------------------+
            //     | 12 | 13 | 14 | 15 |        | 14 | 15 | 12 | 13 |
            //     +-------------------+        +-------------------+

            row1 = Sse2.Shuffle(row1, 0b_10_01_00_11);
            row3 = Sse2.Shuffle(row3, 0b_00_11_10_01);
            row4 = Sse2.Shuffle(row4, 0b_01_00_11_10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G1(Vector128<byte> r16, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, ref Vector128<uint> row4, Vector128<uint> b0)
        {
            row1 = Sse2.Add(Sse2.Add(row1, b0), row2);
            row4 = Sse2.Xor(row4, row1);
            row4 = Ssse3.Shuffle(row4.AsByte(), r16).AsUInt32();

            row3 = Sse2.Add(row3, row4);
            row2 = Sse2.Xor(row2, row3);
            row2 = Sse2.Xor(Sse2.ShiftRightLogical(row2, 12), Sse2.ShiftLeftLogical(row2, 32 - 12));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G2(Vector128<byte> r8, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, ref Vector128<uint> row4, Vector128<uint> b0)
        {
            row1 = Sse2.Add(Sse2.Add(row1, b0), row2);
            row4 = Sse2.Xor(row4, row1);
            row4 = Ssse3.Shuffle(row4.AsByte(), r8).AsUInt32();

            row3 = Sse2.Add(row3, row4);
            row2 = Sse2.Xor(row2, row3);
            row2 = Sse2.Xor(Sse2.ShiftRightLogical(row2, 7), Sse2.ShiftLeftLogical(row2, 32 - 7));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Undiagonalize(ref Vector128<uint> row1, ref Vector128<uint> row3, ref Vector128<uint> row4)
        {
            //     +-------------------+        +-------------------+
            //     |  3 |  0 |  1 |  2 |        |  0 |  1 |  2 |  3 |
            //     +-------------------+        +-------------------+
            //     |  9 | 10 | 11 |  8 |  --->  |  8 |  9 | 10 | 11 |
            //     +-------------------+        +-------------------+
            //     | 14 | 15 | 12 | 13 |        | 12 | 13 | 14 | 15 |
            //     +-------------------+        +-------------------+

            row1 = Sse2.Shuffle(row1, 0b_00_11_10_01);
            row3 = Sse2.Shuffle(row3, 0b_10_01_00_11);
            row4 = Sse2.Shuffle(row4, 0b_01_00_11_10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<T> LoadVector128<T>(ReadOnlySpan<byte> source) where T : struct
        {
            Debug.Assert(source.Length >= Unsafe.SizeOf<Vector128<byte>>());
            return MemoryMarshal.Read<Vector128<T>>(source);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Store<T>(Vector128<T> vector, Span<byte> destination) where T : struct
        {
            Debug.Assert(destination.Length >= Unsafe.SizeOf<Vector128<byte>>());
            MemoryMarshal.Write(destination, ref vector);
        }
    }
}
#endif
