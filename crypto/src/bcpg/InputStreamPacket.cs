using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for packets that carry a data stream.</summary>
    public class InputStreamPacket
        : Packet
    {
        private readonly BcpgInputStream m_bcpgIn;

        /// <summary>Create a new <see cref="InputStreamPacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        [Obsolete("WIll be removed")]
        public InputStreamPacket(BcpgInputStream bcpgIn)
        {
            m_bcpgIn = bcpgIn;
        }

        internal InputStreamPacket(BcpgInputStream bcpgIn, PacketTag packetTag)
            : this(bcpgIn, packetTag, newPacketFormat: false)
        {
        }

        internal InputStreamPacket(BcpgInputStream bcpgIn, PacketTag packetTag, bool newPacketFormat)
            : base(packetTag, newPacketFormat)
        {
            m_bcpgIn = bcpgIn;
        }

        /// <summary>Note: you can only read from this once...</summary>
        public BcpgInputStream GetInputStream() => m_bcpgIn;
    }
}
