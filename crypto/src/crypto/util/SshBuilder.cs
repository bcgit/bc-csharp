using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Utilities
{
    internal class SshBuilder
    {
        private readonly MemoryStream bos = new MemoryStream();

        public void U32(uint value)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[4];
            Pack.UInt32_To_BE(value, buf);
            bos.Write(buf);
#else
            bos.WriteByte(Convert.ToByte(value >> 24 & 0xFF));
            bos.WriteByte(Convert.ToByte(value >> 16 & 0xFF));
            bos.WriteByte(Convert.ToByte(value >> 8 & 0xFF));
            bos.WriteByte(Convert.ToByte(value & 0xFF));
#endif
        }

        public void WriteMpint(BigInteger n)
        {
            WriteBlock(n.ToByteArray());
        }

        public void WriteBlock(byte[] value)
        {
            U32((uint)value.Length);
            WriteBytes(value);
        }

        public void WriteBytes(byte[] value)
        {
            try
            {
                bos.Write(value, 0, value.Length);
            }
            catch (IOException e)
            {
                throw new InvalidOperationException(e.Message, e);
            }
        }

        public void WriteStringAscii(string str)
        {
            WriteBlock(Encoding.ASCII.GetBytes(str));
        }

        public void WriteStringUtf8(string str)
        {
            WriteBlock(Encoding.UTF8.GetBytes(str));
        }

        public byte[] GetBytes()
        {
            return bos.ToArray();
        }

        public byte[] GetPaddedBytes()
        {
            return GetPaddedBytes(8);
        }

        public byte[] GetPaddedBytes(int blockSize)
        {
            int align = (int)bos.Length % blockSize;
            if (0 != align)
            {
                int padCount = blockSize - align;
                for (int i = 1; i <= padCount; ++i)
                {
                    bos.WriteByte(Convert.ToByte(i));
                }
            }
            return bos.ToArray();
        }
    }
}
