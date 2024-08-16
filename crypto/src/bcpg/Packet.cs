using System;

namespace Org.BouncyCastle.Bcpg
{
    // TODO Add packet tag at this level (see bc-java), and IsCritical property
    public class Packet
        //: PacketTag
    {
        private readonly PacketTag packetTag;

        // for API backward compatibility
        // it's unlikely this is being used, but just in case we'll mark
        // unknown inputs as reserved.
        public Packet()
            : this(PacketTag.Reserved)
        {
        }

        public Packet(PacketTag packetTag)
        {
            this.packetTag = packetTag;
        }

        public PacketTag Tag => packetTag;

        /// <summary>
        /// Returns whether the packet is to be considered critical for v6 implementations.
        ///    * Packets with tags less or equal to 39 are critical.
        ///    * Tags 40 to 59 are reserved for unassigned, non-critical packets.
        ///    * Tags 60 to 63 are non-critical private or experimental packets.
        /// <seealso href="https://www.rfc-editor.org/rfc/rfc9580#name-packet-criticality"/>
        /// </summary>
        public bool IsCritical => (int)Tag <= 39;
    }

}