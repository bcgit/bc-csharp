using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMOtsSignature
        : IEncodable
    {
        private readonly LMOtsParameters m_paramType;
        private readonly byte[] m_C;
        private readonly byte[] m_y;

        public LMOtsSignature(LMOtsParameters ParamType, byte[] c, byte[] y)
        {
            m_paramType = ParamType;
            m_C = c;
            m_y = y;
        }

        public static LMOtsSignature GetInstance(object src)
        {
            if (src is LMOtsSignature lmOtsSignature)
            {
                return lmOtsSignature;
            }
            //TODO replace inputstreams with something
            
            else if (src is BinaryReader binaryReader)
            {
                byte[] data = binaryReader.ReadBytes(4);
                Array.Reverse(data);
                int index = BitConverter.ToInt32(data, 0);
                LMOtsParameters type = LMOtsParameters.GetParametersByID(index);
                byte[] C = new byte[type.N];

                binaryReader.Read(C, 0, C.Length);
            
                byte[] sig = new byte[type.P * type.N];
                binaryReader.Read(sig, 0, sig.Length);

                return new LMOtsSignature(type, C, sig);
            }
            else if (src is byte[] bytes)
            {
                BinaryReader input = null;
                try // 1.5 / 1.4 compatibility
                {
                    input = new BinaryReader(new MemoryStream(bytes, false));
                    return GetInstance(input);
                }
                finally
                {
                    if (input != null) input.Close();
                }
            }
            else if (src is MemoryStream memoryStream)
            {
                return GetInstance(Streams.ReadAll(memoryStream));
            }
            throw new Exception ($"cannot parse {src}");
        }

        public LMOtsParameters ParamType => m_paramType;

        // FIXME
        public byte[] C => m_C;

        // FIXME
        public byte[] Y => m_y;

        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;
            if (!(obj is LMOtsSignature that))
                return false;

            return Objects.Equals(m_paramType, that.m_paramType)
                && Arrays.AreEqual(m_C, that.m_C)
                && Arrays.AreEqual(m_y, that.m_y);
        }

        public override int GetHashCode()
        {
            int result = Objects.GetHashCode(m_paramType);
            result = 31 * result + Arrays.GetHashCode(m_C);
            result = 31 * result + Arrays.GetHashCode(m_y);
            return result;
        }

        public byte[] GetEncoded()
        {
            return Composer.Compose()
                .U32Str(m_paramType.ID)
                .Bytes(m_C)
                .Bytes(m_y)
                .Build();
        }
    }
}