#if NETCOREAPP3_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

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
        public static void Compress(bool isFinal, Span<uint> hashBuffer, ReadOnlySpan<byte> dataBuffer, uint totalSegmentsLow, uint totalSegmentsHigh, ReadOnlySpan<uint> blakeIV)
        {
            if(!Sse41.IsSupported || !BitConverter.IsLittleEndian)
                throw new PlatformNotSupportedException(nameof(Blake2s_X86));

            Debug.Assert(dataBuffer.Length >= 128);
            Debug.Assert(hashBuffer.Length >= 8);

            unchecked
            {
                Vector128<byte> r8 = Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
                Vector128<byte> r16 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

                var hashBytes = MemoryMarshal.AsBytes(hashBuffer);
                var ivBytes = MemoryMarshal.AsBytes(blakeIV);

                var r_14 = isFinal ? uint.MaxValue : 0;
                var t_0 = Vector128.Create(totalSegmentsLow, totalSegmentsHigh, r_14, 0);

                Vector128<uint> row1 = VectorExtensions.LoadVector128<uint>(hashBytes);
                Vector128<uint> row2 = VectorExtensions.LoadVector128<uint>(hashBytes[Vector128<byte>.Count..]);
                Vector128<uint> row3 = VectorExtensions.LoadVector128<uint>(ivBytes);
                Vector128<uint> row4 = VectorExtensions.LoadVector128<uint>(ivBytes[Vector128<byte>.Count..]);
                row4 = Sse2.Xor(row4, t_0);

                Vector128<uint> orig_1 = row1;
                Vector128<uint> orig_2 = row2;

                Perform10Rounds(r8, r16, dataBuffer, ref row1, ref row2, ref row3, ref row4);

                row1 = Sse2.Xor(row1, row3);
                row2 = Sse2.Xor(row2, row4);
                row1 = Sse2.Xor(row1, orig_1);
                row2 = Sse2.Xor(row2, orig_2);

                row1.Store(hashBytes);
                row2.Store(hashBytes[Vector128<byte>.Count..]);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Perform10Rounds(Vector128<byte> r8, Vector128<byte> r16, ReadOnlySpan<byte> m, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, ref Vector128<uint> row4)
        {
            Debug.Assert(m.Length >= 128);

            unchecked
            {
                #region Rounds
                //ROUND 1
                var m0 = VectorExtensions.BroadcastVector64ToVector128<uint>(m);
                var m1 = VectorExtensions.BroadcastVector64ToVector128<uint>(m[Unsafe.SizeOf<Vector128<uint>>()..]);
                var m2 = VectorExtensions.BroadcastVector64ToVector128<uint>(m[(Unsafe.SizeOf<Vector128<uint>>() * 2)..]);
                var m3 = VectorExtensions.BroadcastVector64ToVector128<uint>(m[(Unsafe.SizeOf<Vector128<uint>>() * 3)..]);

                var t0 = Sse2.UnpackLow(m0, m1);
                var t1 = Sse2.UnpackLow(m2, m3);
                var b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m0, m1);
                t1 = Sse2.UnpackHigh(m2, m3);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                var m4 = VectorExtensions.BroadcastVector64ToVector128<uint>(m[(Unsafe.SizeOf<Vector128<uint>>() * 4)..]);
                var m5 = VectorExtensions.BroadcastVector64ToVector128<uint>(m[(Unsafe.SizeOf<Vector128<uint>>() * 5)..]);
                var m6 = VectorExtensions.BroadcastVector64ToVector128<uint>(m[(Unsafe.SizeOf<Vector128<uint>>() * 6)..]);
                var m7 = VectorExtensions.BroadcastVector64ToVector128<uint>(m[(Unsafe.SizeOf<Vector128<uint>>() * 7)..]);

                t0 = Sse2.UnpackLow(m7, m4);
                t1 = Sse2.UnpackLow(m5, m6);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m7, m4);
                t1 = Sse2.UnpackHigh(m5, m6);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 2
                t0 = Sse2.UnpackLow(m7, m2);
                t1 = Sse2.UnpackHigh(m4, m6);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackLow(m5, m4);
                t1 = Ssse3.AlignRight(m3, m7, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Sse2.UnpackHigh(m2, m0);
                t1 = Sse41.Blend(m0.AsUInt16(), m5.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Ssse3.AlignRight(m6, m1, 8);
                t1 = Sse41.Blend(m1.AsUInt16(), m3.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 3
                t0 = Ssse3.AlignRight(m6, m5, 8);
                t1 = Sse2.UnpackHigh(m2, m7);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackLow(m4, m0);
                t1 = Sse41.Blend(m1.AsUInt16(), m6.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Ssse3.AlignRight(m5, m4, 8);
                t1 = Sse2.UnpackHigh(m1, m3);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackLow(m2, m7);
                t1 = Sse41.Blend(m3.AsUInt16(), m0.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 4
                t0 = Sse2.UnpackHigh(m3, m1);
                t1 = Sse2.UnpackHigh(m6, m5);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m4, m0);
                t1 = Sse2.UnpackLow(m6, m7);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Ssse3.AlignRight(m1, m7, 8);
                t1 = Ssse3.Shuffle(m2.AsByte(), r16).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackLow(m4, m3);
                t1 = Sse2.UnpackLow(m5, m0);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 5
                t0 = Sse2.UnpackHigh(m4, m2);
                t1 = Sse2.UnpackLow(m1, m5);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse41.Blend(m0.AsUInt16(), m3.AsUInt16(), 0b_1100_1100).AsUInt32();
                t1 = Sse41.Blend(m2.AsUInt16(), m7.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Ssse3.AlignRight(m7, m1, 8);
                t1 = Ssse3.AlignRight(m3, m5, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m6, m0);
                t1 = Sse2.UnpackLow(m6, m4);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 6
                t0 = Sse2.UnpackLow(m1, m3);
                t1 = Sse2.UnpackLow(m0, m4);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackLow(m6, m5);
                t1 = Sse2.UnpackHigh(m5, m1);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Ssse3.AlignRight(m2, m0, 8);
                t1 = Sse2.UnpackHigh(m3, m7);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m4, m6);
                t1 = Ssse3.AlignRight(m7, m2, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 7
                t0 = Sse41.Blend(m6.AsUInt16(), m0.AsUInt16(), 0b_1100_1100).AsUInt32();
                t1 = Sse2.UnpackLow(m7, m2);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m2, m7);
                t1 = Ssse3.AlignRight(m5, m6, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Sse2.UnpackLow(m4, m0);
                t1 = Sse41.Blend(m3.AsUInt16(), m4.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m5, m3);
                t1 = Ssse3.Shuffle(m1.AsByte(), r16).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 8
                t0 = Sse2.UnpackHigh(m6, m3);
                t1 = Sse41.Blend(m6.AsUInt16(), m1.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Ssse3.AlignRight(m7, m5, 8);
                t1 = Sse2.UnpackHigh(m0, m4);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Sse41.Blend(m1.AsUInt16(), m2.AsUInt16(), 0b_1100_1100).AsUInt32();
                t1 = Ssse3.AlignRight(m4, m7, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackLow(m5, m0);
                t1 = Sse2.UnpackLow(m2, m3);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 9
                t0 = Sse2.UnpackLow(m3, m7);
                t1 = Ssse3.AlignRight(m0, m5, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackHigh(m7, m4);
                t1 = Ssse3.AlignRight(m4, m1, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Sse2.UnpackLow(m5, m6);
                t1 = Sse2.UnpackHigh(m6, m0);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Ssse3.AlignRight(m1, m2, 8);
                t1 = Ssse3.AlignRight(m2, m3, 8);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);

                //ROUND 10
                t0 = Sse2.UnpackLow(m5, m4);
                t1 = Sse2.UnpackHigh(m3, m0);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse2.UnpackLow(m1, m2);
                t1 = Sse41.Blend(m3.AsUInt16(), m2.AsUInt16(), 0b_1100_1100).AsUInt32();
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Diagonalize(ref row1, ref row3, ref row4);

                t0 = Sse2.UnpackHigh(m6, m7);
                t1 = Sse2.UnpackHigh(m4, m1);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G1(r16, ref row1, ref row2, ref row3, ref row4, b0);

                t0 = Sse41.Blend(m0.AsUInt16(), m5.AsUInt16(), 0b_1100_1100).AsUInt32();
                t1 = Sse2.UnpackLow(m7, m6);
                b0 = Sse41.Blend(t0.AsUInt16(), t1.AsUInt16(), 0b_1111_0000).AsUInt32();

                G2(r8, ref row1, ref row2, ref row3, ref row4, b0);

                Undiagonalize(ref row1, ref row3, ref row4);
                #endregion
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Diagonalize(ref Vector128<uint> row1, ref Vector128<uint> row3, ref Vector128<uint> row4)
        {
            unchecked
            {
                //     +-------------------+
                //     |  0 |  1 |  2 |  3 |
                //     +-------------------+
                //     |  8 |  9 | 10 | 11 |
                //     +-------------------+
                //     | 12 | 13 | 14 | 15 |
                //     +-------------------+
                //         --->
                //     +-------------------+
                //     |  3 |  0 |  1 |  2 |
                //     +-------------------+
                //     |  9 | 10 | 11 |  8 |
                //     +-------------------+
                //     | 14 | 15 | 12 | 13 |
                //     +-------------------+

                row1 = Sse2.Shuffle(row1, 0b_10_01_00_11);
                row3 = Sse2.Shuffle(row3, 0b_00_11_10_01);
                row4 = Sse2.Shuffle(row4, 0b_01_00_11_10);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G1(Vector128<byte> r16, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, ref Vector128<uint> row4, Vector128<uint> b0)
        {
            unchecked
            {
                row1 = Sse2.Add(Sse2.Add(row1, b0), row2);
                row4 = Sse2.Xor(row4, row1);
                row4 = Ssse3.Shuffle(row4.AsByte(), r16).AsUInt32();

                row3 = Sse2.Add(row3, row4);
                row2 = Sse2.Xor(row2, row3);
                row2 = RotateElement(row2, 12);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G2(Vector128<byte> r8, ref Vector128<uint> row1, ref Vector128<uint> row2, ref Vector128<uint> row3, ref Vector128<uint> row4, Vector128<uint> b0)
        {
            unchecked
            {
                row1 = Sse2.Add(Sse2.Add(row1, b0), row2);
                row4 = Sse2.Xor(row4, row1);
                row4 = Ssse3.Shuffle(row4.AsByte(), r8).AsUInt32();

                row3 = Sse2.Add(row3, row4);
                row2 = Sse2.Xor(row2, row3);
                row2 = RotateElement(row2, 7);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static Vector128<uint> RotateElement(Vector128<uint> vector, byte shift)
        {
            Debug.Assert(shift < sizeof(uint));
            return Sse2.Or(Sse2.ShiftLeftLogical(vector, shift), Sse2.ShiftRightLogical(vector, (byte)(sizeof(ulong) - shift)));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Undiagonalize(ref Vector128<uint> row1, ref Vector128<uint> row3, ref Vector128<uint> row4)
        {
            unchecked
            {
                //     +-------------------+
                //     |  3 |  0 |  1 |  2 |
                //     +-------------------+
                //     |  9 | 10 | 11 |  8 |
                //     +-------------------+
                //     | 14 | 15 | 12 | 13 |
                //     +-------------------+
                //         --->
                //     +-------------------+
                //     |  0 |  1 |  2 |  3 |
                //     +-------------------+
                //     |  8 |  9 | 10 | 11 |
                //     +-------------------+
                //     | 12 | 13 | 14 | 15 |
                //     +-------------------+

                row1 = Sse2.Shuffle(row1, 0b_00_11_10_01);
                row3 = Sse2.Shuffle(row3, 0b_10_01_00_11);
                row4 = Sse2.Shuffle(row4, 0b_01_00_11_10);
            }
        }
    }
}
#endif
