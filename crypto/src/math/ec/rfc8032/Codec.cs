using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
#endif

namespace Org.BouncyCastle.Math.EC.Rfc8032
{
    internal static class Codec
    {
        internal static uint Decode16(byte[] bs, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReadUInt16LittleEndian(bs.AsSpan(off));
#else
            uint n = bs[off];
            n |= (uint)bs[++off] << 8;
            return n;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static uint Decode16(ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt16LittleEndian(bs);
        }
#endif

        internal static uint Decode24(byte[] bs, int off)
        {
            uint n = bs[off];
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off] << 16;
            return n;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static uint Decode24(ReadOnlySpan<byte> bs)
        {
            uint n = bs[0];
            n |= (uint)bs[1] << 8;
            n |= (uint)bs[2] << 16;
            return n;
        }
#endif

        internal static uint Decode32(byte[] bs, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BinaryPrimitives.ReadUInt32LittleEndian(bs.AsSpan(off));
#else
            uint n = bs[off];
            n |= (uint)bs[++off] << 8;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 24;
            return n;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static uint Decode32(ReadOnlySpan<byte> bs)
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(bs);
        }
#endif

        internal static void Decode32(byte[] bs, int bsOff, uint[] n, int nOff, int nLen)
        {
            for (int i = 0; i < nLen; ++i)
            {
                n[nOff + i] = Decode32(bs, bsOff + i * 4);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Decode32(ReadOnlySpan<byte> bs, Span<uint> n)
        {
            for (int i = 0; i < n.Length; ++i)
            {
                n[i] = Decode32(bs[(i * 4)..]);
            }
        }
#endif

        internal static void Encode24(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n >> 16);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Encode24(uint n, Span<byte> bs)
        {
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
            bs[2] = (byte)(n >> 16);
        }
#endif

        internal static void Encode32(uint n, byte[] bs, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            BinaryPrimitives.WriteUInt32LittleEndian(bs.AsSpan(off), n);
#else
            bs[  off] = (byte)(n      );
            bs[++off] = (byte)(n >>  8);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 24);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Encode32(uint n, Span<byte> bs)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(bs, n);
        }
#endif

        internal static void Encode56(ulong n, byte[] bs, int off)
        {
            Encode32((uint)n, bs, off);
            Encode24((uint)(n >> 32), bs, off + 4);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void Encode56(ulong n, Span<byte> bs)
        {
            Encode32((uint)n, bs);
            Encode24((uint)(n >> 32), bs[4..]);
        }
#endif
    }
}
