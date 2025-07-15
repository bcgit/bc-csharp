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

        public UserAttributePacket(BcpgInputStream bcpgIn)
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

        public UserAttributePacket(UserAttributeSubpacket[] subpackets)
        {
            m_subpackets = subpackets;
        }

        public UserAttributeSubpacket[] GetSubpackets() => m_subpackets;

        public override void Encode(BcpgOutputStream bcpgOut)
        {
            MemoryStream bOut = new MemoryStream();

            for (int i = 0; i != m_subpackets.Length; i++)
            {
                m_subpackets[i].Encode(bOut);
            }

            bcpgOut.WritePacket(PacketTag.UserAttribute, bOut.ToArray());
        }
    }
}
