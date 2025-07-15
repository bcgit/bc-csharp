using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a PGP packet.</remarks>
    public abstract class ContainedPacket
        : Packet
    {
        public byte[] GetEncoded()
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut))
            {
                Encode(pOut);
            }
            return bOut.ToArray();
        }

		public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}
