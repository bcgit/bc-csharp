using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic type for a PGP packet.</remarks>
    public abstract class ContainedPacket
        : Packet
    {
        [Obsolete("Will be removed")]
        public ContainedPacket()
            : base()
        {
        }

        internal ContainedPacket(PacketTag packetTag)
            : this(packetTag, false)
        {
        }

        internal ContainedPacket(PacketTag packetTag, bool newPacketFormat)
            : base(packetTag, newPacketFormat)
        {
        }

        public byte[] GetEncoded() => GetEncoded(PacketFormat.Roundtrip);

        public byte[] GetEncoded(PacketFormat packetFormat)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut, packetFormat))
            {
                Encode(pOut);
            }
            return bOut.ToArray();
        }

        public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}
