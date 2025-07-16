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

        protected internal SignatureSubpacket(SignatureSubpacketTag type, bool critical, bool isLongLength, byte[] data)
        {
            m_type = type;
            m_critical = critical;
            m_longLength = isLongLength;
            m_data = data;
        }

        internal byte[] Data => m_data;

        public SignatureSubpacketTag SubpacketType => m_type;

        public bool IsCritical() => m_critical;

        public bool IsLongLength() => m_longLength;

        /// <summary>Return the generic data making up the packet.</summary>
        public byte[] GetData() => Arrays.Clone(m_data);

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

        public override int GetHashCode() => (m_critical ? 1 : 0) + 7 * (int)m_type + 49 * Arrays.GetHashCode(m_data);

        public override bool Equals(object obj)
        {
            return obj is SignatureSubpacket that
                && this.m_type == that.m_type
                && this.m_critical == that.m_critical
                && Arrays.AreEqual(this.m_data, that.m_data);
        }
    }
}
