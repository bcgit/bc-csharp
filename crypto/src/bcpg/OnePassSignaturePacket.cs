using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Generic signature object</remarks>
    public class OnePassSignaturePacket
        : ContainedPacket
    {
        public const int Version3 = 3;
        public const int Version6 = 6;

        private const int FingerprintLength = 32;

        private readonly int m_version;
        private readonly int m_sigType;
        private readonly HashAlgorithmTag m_hashAlgorithm;
        private readonly PublicKeyAlgorithmTag m_keyAlgorithm;
        private readonly ulong m_keyID;
        private readonly int m_nested;
        private readonly byte[] m_salt;         // v6 only
        private readonly byte[] m_fingerprint;  // v6 only

        internal OnePassSignaturePacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal OnePassSignaturePacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.OnePassSignature, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();
            if (m_version != Version3 && m_version != Version6)
            {
                Streams.Drain(bcpgIn);

                throw new UnsupportedPacketVersionException("Unsupported one-pass signature version: " + m_version);
            }

            m_sigType = bcpgIn.RequireByte();
            m_hashAlgorithm = (HashAlgorithmTag)bcpgIn.RequireByte();
            m_keyAlgorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();

            if (m_version == Version6)
            {
                // RFC 9580 5.4.2: the salt length is not validated here, since it depends on the hash algorithm
                m_salt = new byte[bcpgIn.RequireByte()];
                bcpgIn.ReadFully(m_salt);

                m_fingerprint = new byte[FingerprintLength];
                bcpgIn.ReadFully(m_fingerprint);

                m_keyID = (ulong)FingerprintUtilities.KeyIDFromV6Fingerprint(m_fingerprint);
            }
            else
            {
                m_keyID = StreamUtilities.RequireUInt64BE(bcpgIn);
            }

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

        /// <summary>Create a version 6 one-pass signature packet.</summary>
        /// <param name="salt">The salt of the signature this packet announces.</param>
        /// <param name="fingerprint">The 32-octet fingerprint of the version 6 signing key.</param>
        public OnePassSignaturePacket(int sigType, HashAlgorithmTag hashAlgorithm, PublicKeyAlgorithmTag keyAlgorithm,
            byte[] salt, byte[] fingerprint, bool isNested)
            : base(PacketTag.OnePassSignature, newPacketFormat: true)
        {
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (salt.Length > 255)
                throw new ArgumentException("salt too long", nameof(salt));
            if (fingerprint == null)
                throw new ArgumentNullException(nameof(fingerprint));
            if (fingerprint.Length != FingerprintLength)
                throw new ArgumentException("a version 6 fingerprint has " + FingerprintLength + " octets",
                    nameof(fingerprint));

            m_version = Version6;
            m_sigType = sigType;
            m_hashAlgorithm = hashAlgorithm;
            m_keyAlgorithm = keyAlgorithm;
            m_salt = Arrays.Clone(salt);
            m_fingerprint = Arrays.Clone(fingerprint);
            m_keyID = (ulong)FingerprintUtilities.KeyIDFromV6Fingerprint(m_fingerprint);
            m_nested = isNested ? 0 : 1;
        }

        public int Version => m_version;

        public int SignatureType => m_sigType;

        /// <summary>Whether the signature described by this packet is followed by another one-pass signature.</summary>
        public bool IsNested => m_nested == 0;

        /// <summary>The salt of the announced signature (version 6 only, otherwise null).</summary>
        public byte[] GetSalt() => Arrays.Clone(m_salt);

        /// <summary>The fingerprint of the signing key (version 6 only, otherwise null).</summary>
        public byte[] GetFingerprint() => Arrays.Clone(m_fingerprint);

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
            if (m_version == Version6)
            {
                byte[] v6Body = new byte[5 + m_salt.Length + FingerprintLength + 1];
                v6Body[0] = (byte)m_version;
                v6Body[1] = (byte)m_sigType;
                v6Body[2] = (byte)m_hashAlgorithm;
                v6Body[3] = (byte)m_keyAlgorithm;
                v6Body[4] = (byte)m_salt.Length;
                Array.Copy(m_salt, 0, v6Body, 5, m_salt.Length);
                Array.Copy(m_fingerprint, 0, v6Body, 5 + m_salt.Length, FingerprintLength);
                v6Body[v6Body.Length - 1] = (byte)m_nested;

                bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.OnePassSignature, v6Body);
                return;
            }

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
