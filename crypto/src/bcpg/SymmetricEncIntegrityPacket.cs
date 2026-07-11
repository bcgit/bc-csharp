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

        public static SymmetricEncIntegrityPacket CreateV1Packet() => new SymmetricEncIntegrityPacket();

        private readonly int m_version;

        internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal SymmetricEncIntegrityPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.SymmetricEncryptedIntegrityProtected, newPacketFormat)
        {
            m_version = bcpgIn.RequireByte();
        }

        private SymmetricEncIntegrityPacket()
            : base(bcpgIn: null, PacketTag.SymmetricEncryptedIntegrityProtected)
        {
            m_version = Version1;
        }

        public int Version => m_version;
    }
}
