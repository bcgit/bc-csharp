using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    public sealed class PskIdentity
    {
        private readonly byte[] m_identity;
        private readonly long m_obfuscatedTicketAge;

        public PskIdentity(byte[] identity, long obfuscatedTicketAge)
        {
            if (null == identity)
                throw new ArgumentNullException(nameof(identity));
            if (identity.Length < 1 || !TlsUtilities.IsValidUint16(identity.Length))
                throw new ArgumentException("should have length from 1 to 65535", nameof(identity));
            if (!TlsUtilities.IsValidUint32(obfuscatedTicketAge))
                throw new ArgumentException("should be a uint32", nameof(obfuscatedTicketAge));

            m_identity = identity;
            m_obfuscatedTicketAge = obfuscatedTicketAge;
        }

        public int GetEncodedLength() => 6 + m_identity.Length;

        public byte[] Identity => m_identity;

        public long ObfuscatedTicketAge => m_obfuscatedTicketAge;

        public void Encode(Stream output)
        {
            TlsUtilities.WriteOpaque16(Identity, output);
            TlsUtilities.WriteUint32(ObfuscatedTicketAge, output);
        }

        public static PskIdentity Parse(Stream input)
        {
            byte[] identity = TlsUtilities.ReadOpaque16(input, 1);
            long obfuscatedTicketAge = TlsUtilities.ReadUint32(input);
            return new PskIdentity(identity, obfuscatedTicketAge);
        }

        public override bool Equals(object obj)
        {
            return obj is PskIdentity that
                && m_obfuscatedTicketAge == that.m_obfuscatedTicketAge
                && Arrays.FixedTimeEquals(m_identity, that.m_identity);
        }

        public override int GetHashCode() => Arrays.GetHashCode(m_identity) ^ m_obfuscatedTicketAge.GetHashCode();
    }
}
