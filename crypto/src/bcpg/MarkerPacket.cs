using System.IO;

namespace Org.BouncyCastle.Bcpg
{
	/// <remarks>Basic type for a marker packet.</remarks>
    public class MarkerPacket
        : ContainedPacket
    {
        // "PGP"
        private readonly byte[] marker = { (byte)0x50, (byte)0x47, (byte)0x50 };

        public MarkerPacket(BcpgInputStream bcpgIn)
            :base(PacketTag.Marker)
        {
            bcpgIn.ReadFully(marker);
        }

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.Marker, marker);
        }
    }
}
