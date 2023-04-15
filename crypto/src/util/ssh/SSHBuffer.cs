using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Utilities.SSH
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
                {
                    throw new ArgumentException("magic-number incorrect");
                }
            }

            pos += magic.Length;
        }

        internal SshBuffer(byte[] buffer)
        {
            this.buffer = buffer;
        }

        public int ReadU32()
        {
            if (pos > (buffer.Length - 4))
            {
                throw new ArgumentOutOfRangeException("4 bytes for U32 exceeds buffer.");
            }

            int i = (buffer[pos++] & 0xFF) << 24;
            i |= (buffer[pos++] & 0xFF) << 16;
            i |= (buffer[pos++] & 0xFF) << 8;
            i |= (buffer[pos++] & 0xFF);

            return i;
        }

        public String ReadString()
        {
            return Strings.FromByteArray(ReadBlock());
        }

        public byte[] ReadBlock()
        {
            int len = ReadU32();
            if (len == 0)
            {
                return new byte[0];
            }

            if (pos > (buffer.Length - len))
            {
                throw new ArgumentException("not enough data for block");
            }

            int start = pos; pos += len;
            return Arrays.CopyOfRange(buffer, start, pos);
        }

        public void SkipBlock()
        {
            int len = ReadU32();
            if (pos > (buffer.Length - len))
            {
                throw new ArgumentException("not enough data for block");
            }

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
            {
                return new byte[0];
            }

            if (pos > (buffer.Length - len))
            {
                throw new ArgumentException("not enough data for block");
            }

            int align = len % blockSize;
            if (0 != align)
            {
                throw new ArgumentException("missing padding");
            }

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
                        {
                            throw new ArgumentException("incorrect padding");
                        }
                    }
                }
            }

            return Arrays.CopyOfRange(buffer, start, end);
        }

        public BigInteger ReadBigNumPositive()
        {
            int len = ReadU32();
            if (pos + len > buffer.Length)
            {
                throw new ArgumentException("not enough data for big num");
            }

            int start = pos; pos += len;
            byte[] d = Arrays.CopyOfRange(buffer, start, pos);
            return new BigInteger(1, d);
        }

        public byte[] GetBuffer()
        {
            return Arrays.Clone(buffer);
        }

        public Boolean HasRemaining()
        {
            return pos < buffer.Length;
        }
    }
}
