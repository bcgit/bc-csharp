namespace Org.BouncyCastle.Bcpg
{
    /// <summary>A reserved packet (tag 0), which must not appear in valid data.</summary>
    public class ReservedPacket
        : InputStreamPacket
    {
        /// <summary>Create a new <see cref="ReservedPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public ReservedPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="ReservedPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public ReservedPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.Reserved, newPacketFormat)
        {
        }
    }
}
