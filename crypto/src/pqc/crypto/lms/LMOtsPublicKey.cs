using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMOtsPublicKey
    {
        private readonly LMOtsParameters m_parameters;
        private readonly byte[] m_I;
        private readonly int m_q;
        private readonly byte[] m_K;

        public LMOtsPublicKey(LMOtsParameters parameters, byte[] i, int q, byte[] k)
        {
            m_parameters = parameters;
            m_I = i;
            m_q = q;
            m_K = k;
        }

        public static LMOtsPublicKey GetInstance(object src)
        {
            //todo
            if (src is LMOtsPublicKey lmOtsPublicKey)
            {
                return lmOtsPublicKey;
            }
            else if (src is BinaryReader binaryReader)
            {
                int index = BinaryReaders.ReadInt32BigEndian(binaryReader);
                LMOtsParameters parameter = LMOtsParameters.GetParametersByID(index);

                byte[] I = BinaryReaders.ReadBytesFully(binaryReader, 16);

                int q = BinaryReaders.ReadInt32BigEndian(binaryReader);

                byte[] K = BinaryReaders.ReadBytesFully(binaryReader, parameter.N);

                return new LMOtsPublicKey(parameter, I, q, K);
            }
            else if (src is byte[] bytes)
            {
                BinaryReader input = null;
                try // 1.5 / 1.6 compatibility
                {
                    input = new BinaryReader(new MemoryStream(bytes, false));
                    return GetInstance(input);
                }
                finally
                {
                    if (input != null) input.Close();//todo Platform Dispose
                }
            }
            else if (src is ArraySegment<byte> arraySegment)
            {
                BinaryReader input = null;
                try // 1.5 / 1.6 compatibility
                {
                    input = new BinaryReader(new MemoryStream(arraySegment.Array ?? Array.Empty<byte>(), arraySegment.Offset, arraySegment.Count, false));
                    return GetInstance(input);
                }
                finally
                {
                    if (input != null) input.Close();//todo Platform Dispose
                }
            }
            else if (src is MemoryStream memoryStream)
            {
                return GetInstance(Streams.ReadAll(memoryStream));
            }
            throw new Exception ($"cannot parse {src}");
        }

        public LMOtsParameters Parameters => m_parameters;

        public byte[] I => m_I;

        public int Q => m_q;

        public byte[] K => m_K;

        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;
            if (!(obj is LMOtsPublicKey that))
                return false;

            return m_q == that.m_q
                && Objects.Equals(m_parameters, that.m_parameters)
                && Arrays.AreEqual(m_I, that.m_I)
                && Arrays.AreEqual(m_K, that.m_K);
        }

        public override int GetHashCode()
        {
            int result = Objects.GetHashCode(m_parameters);
            result = 31 * result + Arrays.GetHashCode(m_I);
            result = 31 * result + m_q;
            result = 31 * result + Arrays.GetHashCode(m_K);
            return result;
        }

        public byte[] GetEncoded()
        {
            return Composer.Compose()
                .U32Str(m_parameters.ID)
                .Bytes(m_I)
                .U32Str(m_q)
                .Bytes(m_K)
                .Build();
        }

        internal LmsContext CreateOtsContext(LMOtsSignature signature)
        {
            IDigest ctx = DigestUtilities.GetDigest(m_parameters.DigestOid);

            LmsUtilities.ByteArray(m_I, ctx);
            LmsUtilities.U32Str(m_q, ctx);
            LmsUtilities.U16Str((short)LMOts.D_MESG, ctx);
            LmsUtilities.ByteArray(signature.C, ctx);

            return new LmsContext(this, signature, ctx);
        }

        internal LmsContext CreateOtsContext(LmsSignature signature)
        {
            IDigest ctx = DigestUtilities.GetDigest(m_parameters.DigestOid);

            LmsUtilities.ByteArray(m_I, ctx);
            LmsUtilities.U32Str(m_q, ctx);
            LmsUtilities.U16Str((short)LMOts.D_MESG, ctx);
            LmsUtilities.ByteArray(signature.OtsSignature.C, ctx);

            return new LmsContext(this, signature, ctx);
        }
    }
}
