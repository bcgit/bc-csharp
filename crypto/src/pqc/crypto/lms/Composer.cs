using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /**
    * Type to assist in build LMS messages.
    */
    public sealed class Composer
    {
        //Todo make sure MemoryStream works properly (not sure about byte arrays as inputs)
        private readonly MemoryStream bos = new MemoryStream();

        private Composer()
        {
        }

        public static Composer Compose()
        {
            return new Composer();
        }

        public Composer U64Str(long n)
        {
            U32Str((int)(n >> 32));
            U32Str((int)n);
            return this;
        }

        public Composer U32Str(int n)
        {
            bos.WriteByte((byte)(n >> 24));
            bos.WriteByte((byte)(n >> 16));
            bos.WriteByte((byte)(n >> 8));
            bos.WriteByte((byte)n);
            return this;
        }

        public Composer U16Str(int n)
        {
            n &= 0xFFFF;
            bos.WriteByte((byte)(n >> 8));
            bos.WriteByte((byte)n);
            return this;
        }

        public Composer Bytes(IEncodable[] encodable)
        {
            foreach (var e in encodable)
            {
                byte[] encoding = e.GetEncoded();
                bos.Write(encoding, 0, encoding.Length);// todo count?
            }
            return this;
        }

        public Composer Bytes(IEncodable encodable)
        {
            byte[] encoding = encodable.GetEncoded();
            bos.Write(encoding, 0, encoding.Length);
            return this;
        }

        public Composer Pad(int v, int len)
        {
            for (; len >= 0; len--)
            {
                bos.WriteByte((byte)v);
            }
            return this;
        }

        public Composer Bytes2(byte[][] arrays)
        {
            foreach (byte[] array in arrays)
            {
                bos.Write(array, 0, array.Length); //todo count?
            }
            return this;
        }

        public Composer Bytes2(byte[][] arrays, int start, int end)
        {
            int j = start;
            while (j != end)
            {
                bos.Write(arrays[j], 0, arrays[j].Length);//todo count?
                j++;
            }
            return this;
        }

        public Composer Bytes(byte[] array)
        {
            bos.Write(array, 0, array.Length);//todo count?
            return this;
        }

        public Composer Bytes(byte[] array, int start, int len)
        {
            bos.Write(array, start, len);
            return this;
        }

        public byte[] Build()
        {
            return bos.ToArray();
        }

        public Composer PadUntil(int v, int requiredLen)
        {
            while (bos.Length < requiredLen)
            {
                bos.WriteByte((byte)v);
            }
            return this;
        }

        public Composer Boolean(bool v)
        {
            bos.WriteByte((byte)(v ? 1 : 0));
            return this;
        }
    }
}
