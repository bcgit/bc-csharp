using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a user attribute packet.
    */
    public class UserAttributePacket
        : ContainedPacket
    {
        private readonly UserAttributeSubpacket[] m_subpackets;

        /// <summary>Create a new <see cref="UserAttributePacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public UserAttributePacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        /// <summary>Create a new <see cref="UserAttributePacket"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        /// <param name="newPacketFormat">true if new packet format, false otherwise.</param>
        public UserAttributePacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.UserAttribute, newPacketFormat)
        {
            UserAttributeSubpacketsParser sIn = new UserAttributeSubpacketsParser(bcpgIn);
            UserAttributeSubpacket sub;

            var v = new List<UserAttributeSubpacket>();
            while ((sub = sIn.ReadPacket()) != null)
            {
                v.Add(sub);
            }

            m_subpackets = v.ToArray();
        }

        /// <summary>Create a new <see cref="UserAttributePacket"/>.</summary>
        /// <param name="subpackets">The subpackets.</param>
        public UserAttributePacket(UserAttributeSubpacket[] subpackets)
            : base(PacketTag.UserAttribute)
        {
            m_subpackets = subpackets;
        }

        /// <summary>Return the subpackets.</summary>
        public UserAttributeSubpacket[] GetSubpackets() => m_subpackets;

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();

            for (int i = 0; i != m_subpackets.Length; i++)
            {
                m_subpackets[i].Encode(bOut);
            }

            bcpgOut.WritePacket(HasNewPacketFormat, PacketTag.UserAttribute, bOut.ToArray());
        }
    }
}
