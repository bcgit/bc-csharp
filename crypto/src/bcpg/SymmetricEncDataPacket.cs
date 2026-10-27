namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic type for a symmetric key encrypted packet.</remarks>
    public class SymmetricEncDataPacket
        : InputStreamPacket
    {
        /// <summary>Create a new <see cref="SymmetricEncDataPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public SymmetricEncDataPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="SymmetricEncDataPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public SymmetricEncDataPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(bcpgIn, PacketTag.SymmetricKeyEncrypted, newPacketFormat)
        {
        }

        /// <summary>Create a new <see cref="SymmetricEncDataPacket"/>.</summary>
        public SymmetricEncDataPacket()
            : base(bcpgIn: null, PacketTag.SymmetricKeyEncrypted)
        {
        }
    }
}
