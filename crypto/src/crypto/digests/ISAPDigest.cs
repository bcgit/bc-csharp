using System;
using System.IO;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public sealed class IsapDigest
        : IDigest
    {
        private readonly MemoryStream buffer = new MemoryStream();
        private ulong x0, x1, x2, x3, x4;

        public string AlgorithmName => "ISAP Hash";

        public int GetDigestSize() => 32;

        public int GetByteLength() => 8;

        public void Update(byte input)
        {
            buffer.WriteByte(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            Check.DataLength(input, inOff, inLen, "input buffer too short");

            buffer.Write(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            buffer.Write(input);
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            Check.OutputLength(output, outOff, 32, "output buffer is too short");

            /* init state */
            x0 = 17191252062196199485UL;
            x1 = 10066134719181819906UL;
            x2 = 13009371945472744034UL;
            x3 = 4834782570098516968UL;
            x4 = 3787428097924915520UL;

            byte[] input = buffer.GetBuffer();
            int len = Convert.ToInt32(buffer.Length);

            int pos = 0;
            while (len >= 8)
            {
                x0 ^= Pack.BE_To_UInt64(input, pos);
                pos += 8;
                len -= 8;
                P12();
            }
            x0 ^= 0x80UL << ((7 - len) << 3);
            if (len > 0)
            {
                x0 ^= Pack.BE_To_UInt64_High(input, pos, len);
            }

            for (int i = 0; i < 4; ++i)
            {
                P12();
                Pack.UInt64_To_BE(x0, output, outOff + (i << 3));
            }

            return 32;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            Check.OutputLength(output, 32, "output buffer is too short");

            /* init state */
            x0 = 17191252062196199485UL;
            x1 = 10066134719181819906UL;
            x2 = 13009371945472744034UL;
            x3 = 4834782570098516968UL;
            x4 = 3787428097924915520UL;

            if (!buffer.TryGetBuffer(out var bufferContents))
                throw new UnauthorizedAccessException();

            var input = bufferContents.AsSpan();
            while (input.Length >= 8)
            {
                x0 ^= Pack.BE_To_UInt64(input);
                input = input[8..];
                P12();
            }
            x0 ^= 0x80UL << ((7 - input.Length) << 3);
            if (!input.IsEmpty)
            {
                x0 ^= Pack.BE_To_UInt64_High(input);
            }

            for (int i = 0; i < 4; ++i)
            {
                P12();
                Pack.UInt64_To_BE(x0, output[(i << 3)..]);
            }

            return 32;
        }
#endif

        public void Reset()
        {
            buffer.SetLength(0);
        }

        private void P12()
        {
            ROUND(0xf0);
            ROUND(0xe1);
            ROUND(0xd2);
            ROUND(0xc3);
            ROUND(0xb4);
            ROUND(0xa5);
            ROUND(0x96);
            ROUND(0x87);
            ROUND(0x78);
            ROUND(0x69);
            ROUND(0x5a);
            ROUND(0x4b);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void ROUND(ulong C)
        {
            ulong t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
            ulong t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
            ulong t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
            ulong t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
            ulong t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
            x0 = t0 ^ Longs.RotateRight(t0, 19) ^ Longs.RotateRight(t0, 28);
            x1 = t1 ^ Longs.RotateRight(t1, 39) ^ Longs.RotateRight(t1, 61);
            x2 = ~(t2 ^ Longs.RotateRight(t2, 1) ^ Longs.RotateRight(t2, 6));
            x3 = t3 ^ Longs.RotateRight(t3, 10) ^ Longs.RotateRight(t3, 17);
            x4 = t4 ^ Longs.RotateRight(t4, 7) ^ Longs.RotateRight(t4, 41);
        }
    }
}
