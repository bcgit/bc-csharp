using System;

namespace Org.BouncyCastle.Bcpg
{
    public class Packet
    {
        private readonly PacketTag m_packetTag;
        private readonly bool m_newPacketFormat;

        [Obsolete("Will be removed")]
        public Packet()
            : this(PacketTag.Reserved)
        {
        }

        internal Packet(PacketTag packetTag)
            : this(packetTag, newPacketFormat: false)
        {
        }

        internal Packet(PacketTag packetTag, bool newPacketFormat)
        {
            m_packetTag = packetTag;
            m_newPacketFormat = newPacketFormat;
        }

        public bool HasNewPacketFormat => m_newPacketFormat;

        /// <summary>Returns whether the packet is to be considered critical for v6 implementations.</summary>
        /// <remarks>
        /// Packets with tags less than or equal to 39 are critical.
        /// Tags 40 to 59 are reserved for unassigned, non-critical packets.
        /// Tags 60 to 63 are non-critical private or experimental packets.
        /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-tags">OpenPGP - Packet Tags</see>
        /// </remarks>
        public bool IsCritical => (int)m_packetTag <= 39;

        public PacketTag PacketTag => m_packetTag;
    }
}
