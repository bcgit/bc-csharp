using System;

using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Container for a list of user attribute subpackets.</summary>
    public class PgpUserAttributeSubpacketVector
        : IUserDataPacket
    {
        public static PgpUserAttributeSubpacketVector FromSubpackets(UserAttributeSubpacket[] packets) =>
            new PgpUserAttributeSubpacketVector(packets ?? Array.Empty<UserAttributeSubpacket>());

        private readonly UserAttributeSubpacket[] m_packets;

        internal PgpUserAttributeSubpacketVector(UserAttributeSubpacket[] packets)
        {
            m_packets = packets;
        }

        public UserAttributeSubpacket GetSubpacket(UserAttributeSubpacketTag type)
        {
            for (int i = 0; i != m_packets.Length; i++)
            {
                if (m_packets[i].SubpacketType == type)
                    return m_packets[i];
            }

            return null;
        }

        public ImageAttrib GetImageAttribute()
        {
            UserAttributeSubpacket p = GetSubpacket(UserAttributeSubpacketTag.ImageAttribute);

            return p == null ? null : (ImageAttrib)p;
        }

        internal UserAttributeSubpacket[] ToSubpacketArray() => m_packets;

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            if (!(obj is PgpUserAttributeSubpacketVector that))
                return false;

            if (this.m_packets.Length != that.m_packets.Length)
                return false;

            for (int i = 0; i != m_packets.Length; i++)
            {
                if (!this.m_packets[i].Equals(that.m_packets[i]))
                    return false;
            }

            return true;
        }

        public override int GetHashCode() => Arrays.GetHashCode(m_packets);
    }
}
