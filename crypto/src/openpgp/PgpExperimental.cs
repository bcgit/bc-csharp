using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>An experimental packet, kept as raw data.</summary>
    public class PgpExperimental
        : PgpObject
    {
        private readonly ExperimentalPacket m_packet;

        /// <summary>Create a new <see cref="PgpExperimental"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public PgpExperimental(BcpgInputStream bcpgIn)
        {
            Packet packet = bcpgIn.ReadPacket();
            if (!(packet is ExperimentalPacket experimentalPacket))
                throw new IOException("unexpected packet in stream: " + packet);

            m_packet = experimentalPacket;
        }

        /// <summary>Gets the packet tag.</summary>
        public PacketTag PacketTag => m_packet.PacketTag;
    }
}
