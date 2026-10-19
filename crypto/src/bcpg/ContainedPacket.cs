using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic type for a PGP packet.</remarks>
    public abstract class ContainedPacket
        : Packet
    {
        /// <summary>Create a new <see cref="ContainedPacket"/>.</summary>
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

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded() => GetEncoded(PacketFormat.Roundtrip);

        /// <summary>Get the encoding of the packet in the given packet format.</summary>
        /// <param name="packetFormat">The format to use.</param>
        /// <returns>The encoding.</returns>
        public byte[] GetEncoded(PacketFormat packetFormat)
        {
            MemoryStream bOut = new MemoryStream();
            using (var pOut = new BcpgOutputStream(bOut, packetFormat))
            {
                Encode(pOut);
            }
            return bOut.ToArray();
        }

        /// <summary>Write the encoding of this packet.</summary>
        /// <param name="bcpgOut">The stream to write to.</param>
        public abstract void Encode(BcpgOutputStream bcpgOut);
    }
}
