using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
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
            if (src is LMOtsPublicKey lmOtsPublicKey)
                return lmOtsPublicKey;

            if (src is BinaryReader binaryReader)
                return Parse(binaryReader);

            if (src is Stream stream)
                return BinaryReaders.Parse(Parse, stream, leaveOpen: true);

            if (src is byte[] bytes)
                return BinaryReaders.Parse(Parse, new MemoryStream(bytes, false), leaveOpen: false);

            throw new ArgumentException($"cannot parse {src}");
        }

        internal static LMOtsPublicKey Parse(BinaryReader binaryReader)
        {
            int index = BinaryReaders.ReadInt32BigEndian(binaryReader);
            LMOtsParameters parameter = LMOtsParameters.GetParametersByID(index);

            byte[] I = BinaryReaders.ReadBytesFully(binaryReader, 16);

            int q = BinaryReaders.ReadInt32BigEndian(binaryReader);

            byte[] K = BinaryReaders.ReadBytesFully(binaryReader, parameter.N);

            return new LMOtsPublicKey(parameter, I, q, K);
        }

        public byte[] GetI() => Arrays.Clone(m_I);

        public byte[] GetK() => Arrays.Clone(m_K);

        public LMOtsParameters Parameters => m_parameters;

        public int Q => m_q;

        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;

            return obj is LMOtsPublicKey that
                && m_q == that.m_q
                && Objects.Equals(m_parameters, that.m_parameters)
                && Arrays.AreEqual(m_I, that.m_I)
                && Arrays.AreEqual(m_K, that.m_K);
        }

        public override int GetHashCode()
        {
            int result = m_q;
            result = 31 * result + Objects.GetHashCode(m_parameters);
            result = 31 * result + Arrays.GetHashCode(m_I);
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
            IDigest ctx = LmsUtilities.GetDigest(m_parameters);

            LmsUtilities.ByteArray(m_I, ctx);
            LmsUtilities.U32Str(m_q, ctx);
            LmsUtilities.U16Str((short)LMOts.D_MESG, ctx);
#pragma warning disable CS0618 // Type or member is obsolete
            LmsUtilities.ByteArray(signature.C, ctx);
#pragma warning restore CS0618 // Type or member is obsolete

            return new LmsContext(this, signature, ctx);
        }

        internal LmsContext CreateOtsContext(LmsSignature signature)
        {
            IDigest ctx = LmsUtilities.GetDigest(m_parameters);

            LmsUtilities.ByteArray(m_I, ctx);
            LmsUtilities.U32Str(m_q, ctx);
            LmsUtilities.U16Str((short)LMOts.D_MESG, ctx);
#pragma warning disable CS0618 // Type or member is obsolete
            LmsUtilities.ByteArray(signature.OtsSignature.C, ctx);
#pragma warning restore CS0618 // Type or member is obsolete

            return new LmsContext(this, signature, ctx);
        }

        [Obsolete("Use 'GetI' instead")]
        public byte[] I => m_I;

        [Obsolete("Use 'GetK' instead")]
        public byte[] K => m_K;
    }
}
