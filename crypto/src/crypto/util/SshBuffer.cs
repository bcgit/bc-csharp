using System;
using System.Text;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Utilities
{
    internal class SshBuffer
    {
        private readonly byte[] buffer;
        private int pos = 0;

        internal SshBuffer(byte[] magic, byte[] buffer)
        {
            this.buffer = buffer;
            for (int i = 0; i != magic.Length; i++)
            {
                if (magic[i] != buffer[i])
                    throw new ArgumentException("magic-number incorrect");
            }

            pos += magic.Length;
        }

        internal SshBuffer(byte[] buffer)
        {
            this.buffer = buffer;
        }

        public int ReadU32()
        {
            if (pos > buffer.Length - 4)
                throw new InvalidOperationException("4 bytes for U32 exceeds buffer.");

            int i = (int)Pack.BE_To_UInt32(buffer, pos);
            pos += 4;
            return i;
        }

        public string ReadStringAscii()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Encoding.ASCII.GetString(ReadBlockSpan());
#else
            return Encoding.ASCII.GetString(ReadBlock());
#endif
        }

        public string ReadStringUtf8()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Encoding.UTF8.GetString(ReadBlockSpan());
#else
            return Encoding.UTF8.GetString(ReadBlock());
#endif
        }

        public byte[] ReadBlock()
        {
            int len = ReadU32();
            if (len == 0)
                return Arrays.EmptyBytes;
            if (pos > buffer.Length - len)
                throw new InvalidOperationException("not enough data for block");

            int start = pos; pos += len;
            return Arrays.CopyOfRange(buffer, start, pos);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public ReadOnlySpan<byte> ReadBlockSpan()
        {
            int len = ReadU32();
            if (len == 0)
                return ReadOnlySpan<byte>.Empty;
            if (pos > buffer.Length - len)
                throw new InvalidOperationException("not enough data for block");

            int start = pos; pos += len;
            return buffer.AsSpan(start, len);
        }
#endif

        public void SkipBlock()
        {
            int len = ReadU32();
            if (pos > buffer.Length - len)
                throw new InvalidOperationException("not enough data for block");

            pos += len;
        }

        public byte[] ReadPaddedBlock()
        {
            return ReadPaddedBlock(8);
        }

        public byte[] ReadPaddedBlock(int blockSize)
        {
            int len = ReadU32();
            if (len == 0)
                return Arrays.EmptyBytes;
            if (pos > buffer.Length - len)
                throw new InvalidOperationException("not enough data for block");

            int align = len % blockSize;
            if (0 != align)
                throw new InvalidOperationException("missing padding");

            int start = pos; pos += len;
            int end = pos;

            if (len > 0)
            {
                // TODO If encryption is supported, should be constant-time
                int lastByte = buffer[pos - 1] & 0xFF;
                if (0 < lastByte && lastByte < blockSize)
                {
                    int padCount = lastByte;
                    end -= padCount;

                    for (int i = 1, padPos = end; i <= padCount; ++i, ++padPos)
                    {
                        if (i != (buffer[padPos] & 0xFF))
                            throw new InvalidOperationException("incorrect padding");
                    }
                }
            }

            return Arrays.CopyOfRange(buffer, start, end);
        }

        public BigInteger ReadMpint()
        {
            int len = ReadU32();
            if (pos > buffer.Length - len)
                throw new InvalidOperationException("not enough data for big num");

            if (len == 0)
                return BigInteger.Zero;
            if (len == 1 && buffer[pos] == 0)
                throw new InvalidOperationException("Zero MUST be stored with length 0");
            if (len > 1 && buffer[pos] == (byte)-(buffer[pos + 1] >> 7))
                throw new InvalidOperationException("Unnecessary leading bytes MUST NOT be included");

            int start = pos; pos += len;
            return new BigInteger(buffer, start, len);
        }

        public BigInteger ReadMpintPositive()
        {
            BigInteger n = ReadMpint();
            if (n.SignValue < 0)
                throw new InvalidOperationException("Expected a positive mpint");

            return n;
        }

        public bool HasRemaining() => pos < buffer.Length;
    }
}
