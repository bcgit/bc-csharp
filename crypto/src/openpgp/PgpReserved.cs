using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>A reserved packet, kept as raw data.</summary>
    public class PgpReserved
        : PgpObject
    {
        private readonly ReservedPacket m_packet;

        internal PgpReserved(BcpgInputStream bcpgInput)
        {
            Packet packet = bcpgInput.ReadPacket();
            if (!(packet is ReservedPacket reservedPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            m_packet = reservedPacket;
        }
    }
}
