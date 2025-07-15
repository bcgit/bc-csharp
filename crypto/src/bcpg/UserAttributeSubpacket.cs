using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a user attribute sub-packet.</summary>
    public class UserAttributeSubpacket
    {
        private readonly UserAttributeSubpacketTag m_type;
        private readonly bool m_longLength; // we preserve this as not everyone encodes length properly.
        // TODO Make private
        protected readonly byte[] data;

        protected internal UserAttributeSubpacket(UserAttributeSubpacketTag type, byte[] data)
            : this(type, longLength: false, data)
        {
        }

        protected internal UserAttributeSubpacket(UserAttributeSubpacketTag type, bool longLength, byte[] data)
        {
            m_type = type;
            m_longLength = longLength;
            this.data = data;
        }

        internal byte[] Data => data;

        public virtual UserAttributeSubpacketTag SubpacketType => m_type;

        public virtual byte[] GetData() => Arrays.Clone(data);

        public virtual void Encode(Stream os)
        {
            StreamUtilities.WriteNewPacketLength(os, 1 + data.Length, m_longLength);

            os.WriteByte((byte)m_type);
            os.Write(data, 0, data.Length);
        }

        public override bool Equals(object obj)
        {
            return obj is UserAttributeSubpacket that
                && this.m_type == that.m_type
                && Arrays.AreEqual(this.data, that.data);
        }

        public override int GetHashCode() => m_type.GetHashCode() ^ Arrays.GetHashCode(data);
    }
}
