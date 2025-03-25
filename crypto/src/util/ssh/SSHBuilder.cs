using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Utilities.SSH
{
    public class SSHBuilder
    {
        private readonly MemoryStream bos = new MemoryStream();

        [CLSCompliant(false)]
        public void U32(uint value)
        {
            bos.WriteByte(Convert.ToByte((value >> 24) & 0xFF));
            bos.WriteByte(Convert.ToByte((value >> 16) & 0xFF));
            bos.WriteByte(Convert.ToByte((value >> 8) & 0xFF));
            bos.WriteByte(Convert.ToByte(value & 0xFF));
        }

        public void WriteBigNum(BigInteger n)
        {
            WriteBlock(n.ToByteArray());
        }

        public void WriteBlock(byte[] value)
        {
            U32((uint)value.Length);
            try
            {
                bos.Write(value, 0, value.Length);
            }
            catch (IOException e)
            {
                throw new InvalidOperationException(e.Message, e);
            }
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

        public void WriteString(String str)
        {
            WriteBlock(Strings.ToByteArray(str));
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
