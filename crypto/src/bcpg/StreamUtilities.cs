using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    internal static  class StreamUtilities
    {
        [Flags]
        internal enum StreamFlags
        {
            None = 0,
            LongLength = 1,
            Partial = 2,
        }

        internal static int ReadBodyLen(Stream s, out StreamFlags flags)
        {
            flags = StreamFlags.None;

            int b0 = s.ReadByte();
            if (b0 < 0)
                return -1;

            if (b0 < 192)
                return b0;

            if (b0 < 224)
            {
                int b1 = RequireByte(s);
                return ((b0 - 192) << 8) + b1 + 192;
            }

            if (b0 == 255)
            {
                flags |= StreamFlags.LongLength;
                return (int)RequireUInt32BE(s);
            }

            flags |= StreamFlags.Partial;
            return 1 << (b0 & 0x1F);
        }

        internal static int RequireBodyLen(Stream s, out StreamFlags flags)
        {
            int bodyLen = ReadBodyLen(s, out flags);
            if (bodyLen < 0)
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
    }
}
