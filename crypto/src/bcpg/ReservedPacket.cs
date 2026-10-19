namespace Org.BouncyCastle.Bcpg
{
    public class ReservedPacket
        : InputStreamPacket
    {
        /// <summary>Create a new <see cref="ReservedPacket"/>.</summary>
        /// <param name="bcpgIn">The bcpg in.</param>
        public ReservedPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="ReservedPacket"/>.</summary>
        /// <param name="bcpgIn">The bcpg in.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public ReservedPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.Reserved, newPacketFormat)
        {
        }
    }
}
