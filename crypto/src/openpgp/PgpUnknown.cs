using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpUnknown
        : PgpObject
    {
        private readonly UnknownPacket m_packet;

        internal PgpUnknown(BcpgInputStream bcpgIn, bool throwForUnknownCriticalPackets)
        {
            Packet packet = bcpgIn.ReadPacket();
            if (!(packet is UnknownPacket unknownPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            if (throwForUnknownCriticalPackets && unknownPacket.IsCritical)
                throw new IOException("unknown object in stream: " + unknownPacket.PacketTag);

            m_packet = unknownPacket;
        }

        public bool IsCritical => m_packet.IsCritical;

        public PacketTag PacketTag => m_packet.PacketTag;
    }
}
