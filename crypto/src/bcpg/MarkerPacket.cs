namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic type for a marker packet.</remarks>
    public class MarkerPacket
        : ContainedPacket
    {
        // "PGP"
        private readonly byte[] m_marker = { (byte)0x50, (byte)0x47, (byte)0x50 };

        /// <summary>Create a new <see cref="MarkerPacket"/>.</summary>
        /// <param name="bcpgIn">The bcpg in.</param>
        public MarkerPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="MarkerPacket"/>.</summary>
        /// <param name="bcpgIn">The bcpg in.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public MarkerPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.Marker, newPacketFormat)
        {
            bcpgIn.ReadFully(m_marker);
        }

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.Marker, m_marker);
    }
}
