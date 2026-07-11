using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Packet representing non-standard, LibrePGP OCB (AEAD) encrypted data.</summary>
    /// <remarks>
    /// At the moment this appears to exist in the following expired draft only, but it's appearing despite this.
    /// For standardized, interoperable OpenPGP AEAD encrypted data, see <see cref="SymmetricEncIntegrityPacket"/>
    /// of version <see cref="SymmetricEncIntegrityPacket.Version2"/>.
    /// <para>
    /// <see href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-ocb-encrypted-data-packet-t">
    /// LibrePGP -OCB Encrypted Data Packet
    /// </see>
    /// </para>
    /// </remarks>
    public class AeadEncDataPacket
        : InputStreamPacket
    {
        public const byte Version1 = 1;

        private readonly byte m_version;
        private readonly SymmetricKeyAlgorithmTag m_algorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly byte m_chunkSize;
        private readonly byte[] m_iv;

        public AeadEncDataPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        public AeadEncDataPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.AeadEncData, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();
            if (m_version != Version1)
                throw new UnsupportedPacketVersionException("Unknown AEAD packet version: " + m_version);

            m_algorithm = (SymmetricKeyAlgorithmTag)bcpgIn.RequireByte();
            m_aeadAlgorithm = (AeadAlgorithmTag)bcpgIn.RequireByte();
            m_chunkSize = bcpgIn.RequireByte();

            // RFC 9580 - 5.13.2
            if (m_chunkSize < 0 || m_chunkSize > 16)
                throw new MalformedPacketException("chunkSize out of range");

            try
            {
                m_iv = new byte[AeadUtilities.GetIVLength(m_aeadAlgorithm)];
            }
            catch (ArgumentException e)
            {
                throw new MalformedPacketException("Unknown AEAD algorithm ID: " + m_aeadAlgorithm, e);
            }
            bcpgIn.ReadFully(m_iv);
        }

        public AeadEncDataPacket(SymmetricKeyAlgorithmTag algorithm, AeadAlgorithmTag aeadAlgorithm, int chunkSize,
            byte[] iv)
            : base(bcpgIn: null, PacketTag.AeadEncData)
        {
            // RFC 9580 - 5.13.2
            if (chunkSize < 0 || chunkSize > 16)
                throw new ArgumentOutOfRangeException(nameof(chunkSize));

            m_version = Version1;
            m_algorithm = algorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_chunkSize = (byte)chunkSize;
            m_iv = Arrays.Clone(iv);
        }

        public byte Version => m_version;

        public SymmetricKeyAlgorithmTag Algorithm => m_algorithm;

        public AeadAlgorithmTag AeadAlgorithm => m_aeadAlgorithm;

        public int ChunkSize => m_chunkSize;

        internal byte[] IV => m_iv;

        public byte[] GetIV() => m_iv;

        public byte[] GetAAData() => CreateAAData(Version, Algorithm, AeadAlgorithm, ChunkSize);

        public static byte[] CreateAAData(byte version, SymmetricKeyAlgorithmTag symAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int chunkSize)
        {
            byte[] aaData = new byte[5];
            aaData[0] = (byte)PacketTag.AeadEncData | 0xC0;
            aaData[1] = version;
            aaData[2] = (byte)symAlgorithm;
            aaData[3] = (byte)aeadAlgorithm;
            aaData[4] = (byte)chunkSize;
            return aaData;
        }

        [Obsolete("Use 'AeadUtilities.GetIVLength' instead")]
        public static int GetIVLength(AeadAlgorithmTag aeadAlgorithm) => AeadUtilities.GetIVLength(aeadAlgorithm);
    }
}
