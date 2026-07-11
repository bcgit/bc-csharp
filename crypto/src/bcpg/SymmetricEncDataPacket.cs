namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic type for a symmetric key encrypted packet.</remarks>
    public class SymmetricEncDataPacket
        : InputStreamPacket
    {
        public SymmetricEncDataPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        public SymmetricEncDataPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.SymmetricKeyEncrypted, newPacketFormat)
        {
        }

        public SymmetricEncDataPacket()
            : base(bcpgIn: null, PacketTag.SymmetricKeyEncrypted)
        {
        }
    }
}
