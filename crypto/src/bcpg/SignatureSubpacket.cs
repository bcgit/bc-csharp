using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic type for a PGP Signature subpacket.</summary>
    // TODO[api] Make abstract
    public class SignatureSubpacket
    {
        private readonly SignatureSubpacketTag m_type;
        private readonly bool m_critical;
        private readonly bool m_longLength;
        private readonly byte[] m_data;

        /// <summary>Create a new <see cref="SignatureSubpacket"/>.</summary>
        /// <param name="type">The type.</param>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if is long length, false otherwise.</param>
        /// <param name="data">The data.</param>
        protected internal SignatureSubpacket(SignatureSubpacketTag type, bool critical, bool isLongLength, byte[] data)
        {
            m_type = type;
            m_critical = critical;
            m_longLength = isLongLength;
            m_data = data;
        }

        internal byte[] Data => m_data;

        /// <summary>Gets the subpacket type.</summary>
        public SignatureSubpacketTag SubpacketType => m_type;

        /// <summary>Determine whether the subpacket is marked critical.</summary>
        /// <returns>true if it is critical, false otherwise.</returns>
        public bool IsCritical() => m_critical;

        /// <summary>Determine whether the subpacket was encoded with a long length.</summary>
        /// <returns>true if the long length form is used, false otherwise.</returns>
        public bool IsLongLength() => m_longLength;

        /// <summary>Return the generic data making up the packet.</summary>
        public byte[] GetData() => Arrays.Clone(m_data);

        /// <summary>Write the encoding of the subpacket.</summary>
        /// <param name="os">The stream to write to.</param>
        public void Encode(Stream os)
        {
            StreamUtilities.WriteNewPacketLength(os, 1 + m_data.Length, m_longLength);

            byte type = (byte)m_type;
            if (m_critical)
            {
                type |= 0x80;
            }

            os.WriteByte(type);
            os.Write(m_data, 0, m_data.Length);
        }

        /// <inheritdoc/>
        public override int GetHashCode() => (m_critical ? 1 : 0) + 7 * (int)m_type + 49 * Arrays.GetHashCode(m_data);

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return obj is SignatureSubpacket that
                && this.m_type == that.m_type
                && this.m_critical == that.m_critical
                && Arrays.AreEqual(this.m_data, that.m_data);
        }
    }
}
