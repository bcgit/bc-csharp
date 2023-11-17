using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public class LmsSignature
        : IEncodable
    {
        private int q;
        private LMOtsSignature otsSignature;
        private LMSigParameters parameter;
        private byte[][] y;

        public LmsSignature(int q, LMOtsSignature otsSignature, LMSigParameters parameter, byte[][] y)
        {
            this.q = q;
            this.otsSignature = otsSignature;
            this.parameter = parameter;
            this.y = y;
        }

        public static LmsSignature GetInstance(object src)
        {
            if (src is LmsSignature lmsSignature)
                return lmsSignature;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LmsSignature Parse(BinaryReader binaryReader)
        {
            int q = BinaryReaders.ReadInt32BigEndian(binaryReader);

            LMOtsSignature otsSignature = LMOtsSignature.Parse(binaryReader);

            int index = BinaryReaders.ReadInt32BigEndian(binaryReader);
            LMSigParameters type = LMSigParameters.GetParametersByID(index);

            byte[][] path = new byte[type.H][];
            for (int h = 0; h < path.Length; h++)
            {
                path[h] = new byte[type.M];
                binaryReader.Read(path[h], 0, path[h].Length);
            }

            return new LmsSignature(q, otsSignature, type, path);
        }

        public override bool Equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (o == null || GetType() != o.GetType())
            {
                return false;
            }

            LmsSignature that = (LmsSignature)o;

            if (q != that.q)
            {
                return false;
            }
            if (otsSignature != null ? !otsSignature.Equals(that.otsSignature) : that.otsSignature != null)
            {
                return false;
            }
            if (parameter != null ? !parameter.Equals(that.parameter) : that.parameter != null)
            {
                return false;
            }

            return Compare2DArrays(y, that.y);
        }

        private bool Compare2DArrays(byte[][] a, byte[][] b)
        {
            for (int i = 0; i < a.Length; i++)
            {
                for (int j = 0; j < a[0].Length; j++)
                {
                    if (!a[i][j].Equals(b[i][j]))
                        return false;
                }
            }
            return true;
        }

        public override int GetHashCode()
        {
            int result = q;
            result = (31 * result + (otsSignature != null ? otsSignature.GetHashCode() : 0));
            result = (31 * result + (parameter != null ? parameter.GetHashCode() : 0));
            // result = 31 * result + Arrays.GetHashCode(y); //Todo arrays support for 2d arrays?
            return result;
        }

        public byte[] GetEncoded()
        {
            return Composer.Compose()
                .U32Str(q)
                .Bytes(otsSignature.GetEncoded())
                .U32Str(parameter.ID)
                .Bytes2(y)
                .Build();
        }

        public int Q => q;

        public LMOtsSignature OtsSignature => otsSignature;

        public LMSigParameters SigParameters => parameter;

        // FIXME
        public byte[][] Y => y;
    }
}
