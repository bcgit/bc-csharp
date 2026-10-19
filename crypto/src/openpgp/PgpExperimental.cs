using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpExperimental
        : PgpObject
    {
        private readonly ExperimentalPacket m_packet;

        /// <summary>Create a new <see cref="PgpExperimental"/>.</summary>
        /// <param name="bcpgIn">The bcpg in.</param>
        public PgpExperimental(BcpgInputStream bcpgIn)
        {
            Packet packet = bcpgIn.ReadPacket();
            if (!(packet is ExperimentalPacket experimentalPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            m_packet = experimentalPacket;
        }

        public PacketTag PacketTag => m_packet.PacketTag;
    }
}
