using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a PGP packet.</remarks>
    public abstract class ContainedPacket
        : Packet
    {
        protected ContainedPacket(PacketTag packetTag)
            : base(packetTag)
        {
        }

        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                pOut.WritePacket(this);
            }
            return bOut.ToArray();
        }

		public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}
