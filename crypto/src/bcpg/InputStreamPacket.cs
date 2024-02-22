namespace Org.BouncyCastle.Bcpg
{
    public class InputStreamPacket
        : Packet
    {
        private readonly BcpgInputStream bcpgIn;

        // for API backward compatibility
        // it's unlikely this is being used, but just in case we'll mark
        // unknown inputs as reserved.
        public InputStreamPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, PacketTag.Reserved)
        {
        }

        public InputStreamPacket(BcpgInputStream bcpgIn, PacketTag packetTag)
            :base(packetTag)
        {
            this.bcpgIn = bcpgIn;
        }

		/// <summary>Note: you can only read from this once...</summary>
		public BcpgInputStream GetInputStream()
        {
            return bcpgIn;
        }
    }
}
