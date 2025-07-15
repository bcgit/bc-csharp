using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    internal static class StreamUtilities
    {
        [Flags]
        internal enum StreamFlags
        {
            None = 0,
            LongLength = 1,
            Partial = 2,
            Eof = 4
        }

        internal static uint ReadBodyLen(Stream s, out StreamFlags flags)
        {
            flags = StreamFlags.None;

            int b0 = s.ReadByte();
            if (b0 < 0)
            {
                flags = StreamFlags.Eof;
                return 0U;
            }

            if (b0 < 192)
                return (uint)b0;

            if (b0 < 224)
            {
                int b1 = RequireByte(s);
                return (uint)(((b0 - 192) << 8) + b1 + 192);
            }

            if (b0 == 255)
            {
                flags |= StreamFlags.LongLength;
                return RequireUInt32BE(s);
            }

            flags |= StreamFlags.Partial;
            return 1U << (b0 & 0x1F);
        }

        internal static uint RequireBodyLen(Stream s, out StreamFlags streamFlags)
        {
            uint bodyLen = ReadBodyLen(s, out streamFlags);
            if (streamFlags.HasFlag(StreamFlags.Eof))
                throw new EndOfStreamException();
            return bodyLen;
        }

        internal static byte RequireByte(Stream s)
        {
            int b = s.ReadByte();
            if (b < 0)
                throw new EndOfStreamException();
            return (byte)b;
        }

        internal static byte[] RequireBytes(Stream s, int count)
        {
            byte[] bytes = new byte[count];
            RequireBytes(s, bytes);
            return bytes;
        }

        internal static void RequireBytes(Stream s, byte[] buffer) =>
            RequireBytes(s, buffer, 0, buffer.Length);

        internal static void RequireBytes(Stream s, byte[] buffer, int offset, int count)
        {
            if (Streams.ReadFully(s, buffer, offset, count) < count)
                throw new EndOfStreamException();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void RequireBytes(Stream s, Span<byte> buffer)
        {
            if (Streams.ReadFully(s, buffer) != buffer.Length)
                throw new EndOfStreamException();
        }
#endif

        internal static ushort RequireUInt16BE(Stream s)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[2];
#else
            byte[] buf = new byte[2];
#endif
            RequireBytes(s, buf);
            return Pack.BE_To_UInt16(buf);
        }

        internal static uint RequireUInt32BE(Stream s)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[4];
#else
            byte[] buf = new byte[4];
#endif
            RequireBytes(s, buf);
            return Pack.BE_To_UInt32(buf);
        }

        internal static ulong RequireUInt64BE(Stream s)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[8];
#else
            byte[] buf = new byte[8];
#endif
            RequireBytes(s, buf);
            return Pack.BE_To_UInt64(buf);
        }

        internal static void WriteNewPacketLength(Stream s, long bodyLen, bool longLength = false)
        {
            if (longLength || bodyLen > 8383)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> buf = stackalloc byte[5];
                buf[0] = 0xFF;
                Pack.UInt32_To_BE((uint)bodyLen, buf, 1);
                s.Write(buf);
#else
                s.WriteByte(0xFF);
                s.WriteByte((byte)(bodyLen >> 24));
                s.WriteByte((byte)(bodyLen >> 16));
                s.WriteByte((byte)(bodyLen >> 8));
                s.WriteByte((byte)bodyLen);
#endif
            }
            else if (bodyLen < 192)
            {
                s.WriteByte((byte)bodyLen);
            }
            else
            {
                bodyLen -= 192;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> buf = stackalloc byte[2];
                buf[0] = (byte)(((bodyLen >> 8) & 0xFF) + 192);
                buf[1] = (byte)bodyLen;
                s.Write(buf);
#else
                s.WriteByte((byte)(((bodyLen >> 8) & 0xFF) + 192));
                s.WriteByte((byte)bodyLen);
#endif
            }
        }

        internal static void WriteUInt16BE(Stream s, ushort n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[2];
            Pack.UInt16_To_BE(n, buf);
            s.Write(buf);
#else
            s.WriteByte((byte)(n >> 8));
            s.WriteByte((byte)n);
#endif
        }

        internal static void WriteUInt32BE(Stream s, uint n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[4];
            Pack.UInt32_To_BE(n, buf);
            s.Write(buf);
#else
            byte[] buf = new byte[4];
            Pack.UInt32_To_BE(n, buf, 0);
            s.Write(buf, 0, buf.Length);
#endif
        }

        internal static void WriteUInt64BE(Stream s, ulong n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[8];
            Pack.UInt64_To_BE(n, buf);
            s.Write(buf);
#else
            byte[] buf = new byte[8];
            Pack.UInt64_To_BE(n, buf, 0);
            s.Write(buf, 0, buf.Length);
#endif
        }
    }
}
