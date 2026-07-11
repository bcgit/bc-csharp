using System;

namespace Org.BouncyCastle.Bcpg
{
    public class InputStreamPacket
        : Packet
    {
        private readonly BcpgInputStream m_bcpgIn;

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
