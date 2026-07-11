namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a marker packet.</remarks>
    public class MarkerPacket
        : ContainedPacket
    {
        // "PGP"
        private readonly byte[] m_marker = { (byte)0x50, (byte)0x47, (byte)0x50 };

        public MarkerPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        public MarkerPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.Marker, newPacketFormat)
        {
            bcpgIn.ReadFully(m_marker);
        }

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.Marker, m_marker);
    }
}
