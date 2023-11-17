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

        public LMOtsSignature(LMOtsParameters paramType, byte[] c, byte[] y)
        {
            m_paramType = paramType;
            m_C = c;
            m_y = y;
        }

        public static LMOtsSignature GetInstance(object src)
        {
            if (src is LMOtsSignature lmOtsSignature)
                return lmOtsSignature;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LMOtsSignature Parse(BinaryReader binaryReader)
        {
            int index = BinaryReaders.ReadInt32BigEndian(binaryReader);
            LMOtsParameters parameter = LMOtsParameters.GetParametersByID(index);

            byte[] C = BinaryReaders.ReadBytesFully(binaryReader, parameter.N);

            byte[] sig = BinaryReaders.ReadBytesFully(binaryReader, parameter.P * parameter.N);

            return new LMOtsSignature(parameter, C, sig);
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