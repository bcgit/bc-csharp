using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    public class SymmetricEncIntegrityPacket
        : InputStreamPacket
    {
        /// <summary>Version 1 SEIPD packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricKeyEncSessionPacket.Version4"/> or
        /// <see cref="PublicKeyEncSessionPacket.Version3"/>.
        /// </remarks>
        public const int Version1 = 1;

        /// <summary>Version 2 SEIPD packet.</summary>
        /// <remarks>
        /// Used only with <see cref="SymmetricKeyEncSessionPacket.Version6"/> or
        /// <see cref="PublicKeyEncSessionPacket.Version6"/>.
        /// </remarks>
        public const int Version2 = 2;

        /// <summary>The length of the salt in a version 2 SEIPD packet, in octets.</summary>
        public const int SaltLength = 32;

        /// <summary>The largest chunk size octet allowed in a version 2 SEIPD packet.</summary>
        private const int MaxChunkSize = 16;

        public static SymmetricEncIntegrityPacket CreateV1Packet() => new SymmetricEncIntegrityPacket();

        /// <summary>Create the associated data of a version 2 SEIPD packet (RFC 9580 5.13.2).</summary>
        /// <param name="chunkSize">The chunk size octet, i.e. the chunk length is 2^(chunkSize + 6) octets.</param>
        public static byte[] CreateAAData(SymmetricKeyAlgorithmTag cipherAlgorithm, AeadAlgorithmTag aeadAlgorithm,
            int chunkSize)
        {
            return new byte[]
            {
                (byte)PacketTag.SymmetricEncryptedIntegrityProtected | 0xC0,
                Version2,
                (byte)cipherAlgorithm,
                (byte)aeadAlgorithm,
                (byte)chunkSize,
            };
        }

        private readonly int m_version;
        private readonly SymmetricKeyAlgorithmTag m_cipherAlgorithm;    // V2
        private readonly AeadAlgorithmTag m_aeadAlgorithm;              // V2
        private readonly int m_chunkSize;                               // V2
        private readonly byte[] m_salt;                                 // V2

        internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.SymmetricEncryptedIntegrityProtected, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();

            if (m_version == Version2)
            {
                m_cipherAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
                m_aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.RequireByte();

                // RFC 9580 5.13.2 only requires accepting chunk size octets up to 16, which also limits the memory
                // needed to process a chunk.
                m_chunkSize = bcpgIn.RequireByte();
                if (m_chunkSize > MaxChunkSize)
                    throw new MalformedPacketException("Invalid chunk size octet in SEIPD packet: " + m_chunkSize);

                m_salt = new byte[SaltLength];
                bcpgIn.ReadFully(m_salt);
            }
        }

        private SymmetricEncIntegrityPacket()
            : base(bcpgIn: null, PacketTag.SymmetricEncryptedIntegrityProtected)
        {
            m_version = Version1;
        }

        public int Version => m_version;

        /// <summary>The symmetric cipher of a version 2 packet.</summary>
        /// <exception cref="InvalidOperationException">If this is not a version 2 packet.</exception>
        public SymmetricKeyAlgorithmTag CipherAlgorithm
        {
            get
            {
                RequireVersion2();
                return m_cipherAlgorithm;
            }
        }

        /// <summary>The AEAD algorithm of a version 2 packet.</summary>
        /// <exception cref="InvalidOperationException">If this is not a version 2 packet.</exception>
        public AeadAlgorithmTag AeadAlgorithm
        {
            get
            {
                RequireVersion2();
                return m_aeadAlgorithm;
            }
        }

        /// <summary>The chunk size octet of a version 2 packet; the chunk length is 2^(ChunkSize + 6) octets.</summary>
        /// <exception cref="InvalidOperationException">If this is not a version 2 packet.</exception>
        public int ChunkSize
        {
            get
            {
                RequireVersion2();
                return m_chunkSize;
            }
        }

        /// <summary>The salt of a version 2 packet.</summary>
        /// <returns>A copy of the salt.</returns>
        /// <exception cref="InvalidOperationException">If this is not a version 2 packet.</exception>
        public byte[] GetSalt()
        {
            RequireVersion2();
            return Arrays.Clone(m_salt);
        }

        /// <summary>The associated data of a version 2 packet.</summary>
        /// <exception cref="InvalidOperationException">If this is not a version 2 packet.</exception>
        public byte[] GetAAData()
        {
            RequireVersion2();
            return CreateAAData(m_cipherAlgorithm, m_aeadAlgorithm, m_chunkSize);
        }

        private void RequireVersion2()
        {
            if (m_version != Version2)
                throw new InvalidOperationException("only available for version 2 SEIPD packets");
        }
    }
}
