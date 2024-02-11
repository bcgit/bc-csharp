using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpPadding
        : PgpObject
    {
        private readonly PaddingPacket data;

        public PgpPadding(BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is PaddingPacket paddingPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            data = paddingPacket;
        }

        public byte[] GetPadding() => data.GetPadding();
    }
}