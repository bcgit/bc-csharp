using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a user attribute subpacket.</summary>
    public class UserAttributeSubpacket
    {
        private readonly UserAttributeSubpacketTag m_type;
        private readonly bool m_longLength; // we preserve this as not everyone encodes length properly.
        // TODO[api] Make private
        protected readonly byte[] data;

        /// <summary>Create a new <see cref="UserAttributeSubpacket"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="data">The data.</param>
        protected internal UserAttributeSubpacket(UserAttributeSubpacketTag type, byte[] data)
            : this(type, longLength: false, data)
        {
        }

        /// <summary>Create a new <see cref="UserAttributeSubpacket"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="longLength">true if long length, false otherwise.</param>
        /// <param name="data">The data.</param>
        protected internal UserAttributeSubpacket(UserAttributeSubpacketTag type, bool longLength, byte[] data)
        {
            m_type = type;
            m_longLength = longLength;
            this.data = data;
        }

        internal byte[] Data => data;

        /// <summary>Gets the subpacket type.</summary>
        public virtual UserAttributeSubpacketTag SubpacketType => m_type;

        /// <summary>Return the data.</summary>
        public virtual byte[] GetData() => Arrays.Clone(data);

        public virtual void Encode(Stream os)
        {
            StreamUtilities.WriteNewPacketLength(os, 1 + data.Length, m_longLength);

            os.WriteByte((byte)m_type);
            os.Write(data, 0, data.Length);
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return obj is UserAttributeSubpacket that
                && this.m_type == that.m_type
                && Arrays.AreEqual(this.data, that.data);
        }

        /// <inheritdoc/>
        public override int GetHashCode() => m_type.GetHashCode() ^ Arrays.GetHashCode(data);
    }
}
