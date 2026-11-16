using System;

using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Container for a list of user attribute subpackets.</summary>
    public class PgpUserAttributeSubpacketVector
        : IUserDataPacket
    {
        /// <summary>Create a vector from an array of subpackets.</summary>
        /// <param name="packets">The subpackets.</param>
        /// <returns>The vector.</returns>
        public static PgpUserAttributeSubpacketVector FromSubpackets(UserAttributeSubpacket[] packets) =>
            new PgpUserAttributeSubpacketVector(packets ?? Array.Empty<UserAttributeSubpacket>());

        private readonly UserAttributeSubpacket[] m_packets;

        internal PgpUserAttributeSubpacketVector(UserAttributeSubpacket[] packets)
        {
            m_packets = packets;
        }

        /// <summary>Get the first subpacket of the given type.</summary>
        /// <param name="type">The subpacket type.</param>
        /// <returns>The subpacket, or null if there is none.</returns>
        public UserAttributeSubpacket GetSubpacket(UserAttributeSubpacketTag type)
        {
            for (int i = 0; i != m_packets.Length; i++)
            {
                if (m_packets[i].SubpacketType == type)
                    return m_packets[i];
            }

            return null;
        }

        /// <summary>Return the image attribute.</summary>
        public ImageAttrib GetImageAttribute()
        {
            UserAttributeSubpacket p = GetSubpacket(UserAttributeSubpacketTag.ImageAttribute);

            return p == null ? null : (ImageAttrib)p;
        }

        internal UserAttributeSubpacket[] ToSubpacketArray() => m_packets;

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public override int GetHashCode() => Arrays.GetHashCode(m_packets);
    }
}
