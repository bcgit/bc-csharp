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

        /// <summary>Gets a value indicating whether this is critical.</summary>
        public bool IsCritical => m_packet.IsCritical;

        /// <summary>Gets the packet tag.</summary>
        public PacketTag PacketTag => m_packet.PacketTag;
    }
}
