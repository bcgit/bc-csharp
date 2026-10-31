using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic packet for a PGP public key.</summary>
    public class PublicKeyEncSessionPacket
        : ContainedPacket //, PublicKeyAlgorithmTag
    {
        /// <summary>Version 3 PKESK packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricEncIntegrityPacket.Version1">V1 SEIPD</see> or
        /// <see cref="SymmetricEncDataPacket">SED</see> packets.
        /// </remarks>
        public const int Version3 = 3;

        /// <summary>Version 6 PKESK packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricEncIntegrityPacket.Version2">V2 SEIPD</see> packets.
        /// </remarks>
        public const int Version6 = 6;

        public static PublicKeyEncSessionPacket CreateV3Packet(long keyId, PublicKeyAlgorithmTag algorithm,
            byte[][] data)
        {
            return new PublicKeyEncSessionPacket(keyId, algorithm, data);
        }

        /// <summary>Create a version 6 PKESK packet.</summary>
        /// <param name="keyVersion">The version of the recipient key.</param>
        /// <param name="keyFingerprint">
        /// The fingerprint of the recipient key (20 octets for a version 4 key, 32 octets for a version 6 key), or
        /// null for an anonymous recipient.
        /// </param>
        public static PublicKeyEncSessionPacket CreateV6Packet(int keyVersion, byte[] keyFingerprint,
            PublicKeyAlgorithmTag algorithm, byte[][] data)
        {
            return new PublicKeyEncSessionPacket(keyVersion, keyFingerprint, algorithm, data);
        }

        private readonly int m_version;
        private readonly ulong m_keyID;
        private readonly int m_keyVersion;          // v6 only
        private readonly byte[] m_keyFingerprint;   // v6 only
        private readonly PublicKeyAlgorithmTag m_algorithm;
        private readonly byte[][] m_data;

        // Set when the version 6 packet contains MPIs that are not minimally encoded (RFC 9580 3.2)
        internal bool IsMalformed { get; }

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.PublicKeyEncryptedSession, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();
            if (m_version != Version3 && m_version != Version6)
            {
                Streams.Drain(bcpgIn);

                throw new UnsupportedPacketVersionException("Unsupported PKESK version: " + m_version);
            }

            if (m_version == Version3)
            {
                m_keyID = StreamUtilities.RequireUInt64BE(bcpgIn);
            }
            else
            {
                // RFC 9580 5.1.2: the length of the key version and fingerprint, which are absent if it is zero
                int keyInfoLength = bcpgIn.RequireByte();
                if (keyInfoLength > 0)
                {
                    m_keyVersion = bcpgIn.RequireByte();
                    m_keyFingerprint = new byte[keyInfoLength - 1];
                    bcpgIn.ReadFully(m_keyFingerprint);

                    if (m_keyVersion == PublicKeyPacket.Version4)
                    {
                        if (m_keyFingerprint.Length != 20)
                            throw new MalformedPacketException("Invalid version 4 key fingerprint length in PKESK");

                        m_keyID = (ulong)FingerprintUtilities.KeyIDFromFingerprint(m_keyVersion, m_keyFingerprint);
                    }
                    else if (m_keyVersion == PublicKeyPacket.Version6)
                    {
                        if (m_keyFingerprint.Length != 32)
                            throw new MalformedPacketException("Invalid version 6 key fingerprint length in PKESK");

                        m_keyID = (ulong)FingerprintUtilities.KeyIDFromFingerprint(m_keyVersion, m_keyFingerprint);
                    }
                    // Other key versions are kept as they are, but cannot be matched with a key
                }
            }

            m_algorithm = (PublicKeyAlgorithmTag)bcpgIn.RequireByte();

            switch (m_algorithm)
            {
            case PublicKeyAlgorithmTag.RsaEncrypt:
            case PublicKeyAlgorithmTag.RsaGeneral:
            {
                MPInteger m = new MPInteger(bcpgIn);
                m_data = new byte[][]{ m.GetEncoded() };
                IsMalformed = m_version == Version6 && !m.IsMinimal;
                break;
            }
            case PublicKeyAlgorithmTag.ElGamalEncrypt:
            case PublicKeyAlgorithmTag.ElGamalGeneral:
            {
                MPInteger p = new MPInteger(bcpgIn);
                MPInteger g = new MPInteger(bcpgIn);
                m_data = new byte[][]{
                    p.GetEncoded(),
                    g.GetEncoded(),
                };
                IsMalformed = m_version == Version6 && !(p.IsMinimal && g.IsMinimal);
                break;
            }
            default:
                // ECDH, MLKem768_X25519 and algorithms we cannot use: keep the encrypted session key opaque, so that
                // an unusable PKESK does not prevent other recipients from decrypting the message.
                m_data = new byte[][]{ Streams.ReadAll(bcpgIn) };
                if (m_algorithm == PublicKeyAlgorithmTag.ECDH && m_version == Version6)
                {
                    IsMalformed = !IsMinimalMpiPrefix(m_data[0]);
                }
                break;
            }
        }

        /// <summary>Check that the data starts with a minimally encoded MPI (the ECDH ephemeral point).</summary>
        private static bool IsMinimalMpiPrefix(byte[] data)
        {
            if (data.Length < 2)
                return false;

            int bitLength = (data[0] << 8) | data[1];
            int byteLength = (bitLength + 7) / 8;
            if (data.Length < 2 + byteLength)
                return false;
            if (byteLength == 0)
                return true;

            int first = data[2];
            if (first == 0)
                return false;

            int topBits = 0;
            while ((first >> topBits) != 0)
            {
                ++topBits;
            }

            return bitLength == 8 * (byteLength - 1) + topBits;
        }

        public PublicKeyEncSessionPacket(long keyId, PublicKeyAlgorithmTag algorithm, byte[][] data)
            : base(PacketTag.PublicKeyEncryptedSession)
        {
            m_version = Version3;
            m_keyID = (ulong)keyId;
            m_algorithm = algorithm;
            m_data = CloneData(data);
        }

        private PublicKeyEncSessionPacket(int keyVersion, byte[] keyFingerprint, PublicKeyAlgorithmTag algorithm,
            byte[][] data)
            : base(PacketTag.PublicKeyEncryptedSession, newPacketFormat: true)
        {
            m_version = Version6;
            m_algorithm = algorithm;
            m_data = CloneData(data);

            if (keyFingerprint != null)
            {
                if (keyFingerprint.Length > 254)
                    throw new ArgumentException("key fingerprint too long", nameof(keyFingerprint));

                if (keyVersion == PublicKeyPacket.Version4 && keyFingerprint.Length != 20)
                    throw new ArgumentException("a version 4 key fingerprint has 20 octets", nameof(keyFingerprint));
                if (keyVersion == PublicKeyPacket.Version6 && keyFingerprint.Length != 32)
                    throw new ArgumentException("a version 6 key fingerprint has 32 octets", nameof(keyFingerprint));

                m_keyVersion = keyVersion;
                m_keyFingerprint = Arrays.Clone(keyFingerprint);
                m_keyID = (ulong)FingerprintUtilities.KeyIDFromFingerprint(keyVersion, keyFingerprint);
            }
        }

        private static byte[][] CloneData(byte[][] data)
        {
            byte[][] result = new byte[data.Length][];
            for (int i = 0; i < data.Length; ++i)
            {
                result[i] = Arrays.Clone(data[i]);
            }
            return result;
        }

        public int Version => m_version;

        /// <summary>The version of the recipient key (version 6 packets with a recipient only, otherwise 0).</summary>
        public int KeyVersion => m_keyVersion;

        /// <summary>The fingerprint of the recipient key (version 6 packets with a recipient only).</summary>
        /// <returns>A copy of the fingerprint, or null if there is none.</returns>
        public byte[] GetKeyFingerprint() => Arrays.Clone(m_keyFingerprint);

        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)m_keyID;

        public PublicKeyAlgorithmTag Algorithm => m_algorithm;

        public byte[][] GetEncSessionKey() => m_data;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            // version 3: version, key ID, algorithm; version 6: version, key info length, [key info], algorithm
            int keyInfoLength = m_keyFingerprint == null ? 0 : 1 + m_keyFingerprint.Length;
            uint bodyLength = m_version == Version3 ? 1U + 8U + 1U : (uint)(1 + 1 + keyInfoLength + 1);
            foreach (var data in m_data)
            {
                bodyLength += (uint)data.Length;
            }

            bcpgOut.WritePacketHeader(HasNewPacketFormat, PacketTag.PublicKeyEncryptedSession, bodyLength);

            if (m_version == Version3)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> body = stackalloc byte[10];
#else
                byte[] body = new byte[10];
#endif

                body[0] = (byte)m_version;
                Pack.UInt64_To_BE(m_keyID, body, 1);
                body[9] = (byte)m_algorithm;

                bcpgOut.Write(body);
            }
            else
            {
                bcpgOut.WriteByte((byte)m_version);
                bcpgOut.WriteByte((byte)keyInfoLength);
                if (m_keyFingerprint != null)
                {
                    bcpgOut.WriteByte((byte)m_keyVersion);
                    bcpgOut.Write(m_keyFingerprint);
                }
                bcpgOut.WriteByte((byte)m_algorithm);
            }

            foreach (var data in m_data)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                bcpgOut.Write(data.AsSpan());
#else
                bcpgOut.Write(data, 0, data.Length);
#endif
            }
        }
    }
}
