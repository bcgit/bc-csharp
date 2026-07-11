using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature object</remarks>
    public class OnePassSignaturePacket
        : ContainedPacket
    {
        public const int Version3 = 3;
        public const int Version6 = 6;

        private readonly int m_version;
        private readonly int m_sigType;
        private readonly HashAlgorithmTag m_hashAlgorithm;
        private readonly PublicKeyAlgorithmTag m_keyAlgorithm;
        private readonly ulong m_keyID;
        private readonly int m_nested;

        internal OnePassSignaturePacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal OnePassSignaturePacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.OnePassSignature, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();
            m_sigType = bcpgIn.RequireByte();
            m_hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();
            m_keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();
            m_keyID = StreamUtilities.RequireUInt64BE(bcpgIn);
            m_nested = bcpgIn.RequireByte();
        }

        public OnePassSignaturePacket(int sigType, HashAlgorithmTag hashAlgorithm, PublicKeyAlgorithmTag keyAlgorithm,
            long keyId, bool isNested)
            : base(PacketTag.OnePassSignature)
        {
            m_version = Version3;
            m_sigType = sigType;
            m_hashAlgorithm = hashAlgorithm;
            m_keyAlgorithm = keyAlgorithm;
            m_keyID = (ulong)keyId;
            m_nested = isNested ? 0 : 1;
        }

        public int SignatureType => m_sigType;

        /// <summary>The encryption algorithm tag.</summary>
        public PublicKeyAlgorithmTag KeyAlgorithm => m_keyAlgorithm;

        /// <summary>The hash algorithm tag.</summary>
        public HashAlgorithmTag HashAlgorithm => m_hashAlgorithm;

        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)m_keyID;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> body = stackalloc byte[13];
#else
            byte[] body = new byte[13];
#endif

            body[0] = (byte)m_version;
            body[1] = (byte)m_sigType;
            body[2] = (byte)m_hashAlgorithm;
            body[3] = (byte)m_keyAlgorithm;
            Pack.UInt64_To_BE(m_keyID, body, 4);
            body[12] = (byte)m_nested;

            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.OnePassSignature, body);
        }
    }
}
