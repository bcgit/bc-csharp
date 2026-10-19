using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A pre-shared key identity together with its obfuscated ticket age, as used in TLS 1.3.</summary>
    public sealed class PskIdentity
    {
        private readonly byte[] m_identity;
        private readonly long m_obfuscatedTicketAge;

        /// <summary>Create a new <see cref="PskIdentity"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="obfuscatedTicketAge">The obfuscated ticket age.</param>
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

        /// <summary>Return the encoded length.</summary>
        public int GetEncodedLength() => 6 + m_identity.Length;

        /// <summary>Gets the identity.</summary>
        public byte[] Identity => m_identity;

        /// <summary>Gets the obfuscated ticket age.</summary>
        public long ObfuscatedTicketAge => m_obfuscatedTicketAge;

        /// <summary>Encode this identity to a stream.</summary>
        /// <param name="output">The stream to write to.</param>
        public void Encode(Stream output)
        {
            TlsUtilities.WriteOpaque16(Identity, output);
            TlsUtilities.WriteUint32(ObfuscatedTicketAge, output);
        }

        /// <summary>Parse an identity from a stream.</summary>
        /// <param name="input">The stream to read from.</param>
        /// <returns>The identity.</returns>
        public static PskIdentity Parse(Stream input)
        {
            byte[] identity = TlsUtilities.ReadOpaque16(input, 1);
            long obfuscatedTicketAge = TlsUtilities.ReadUint32(input);
            return new PskIdentity(identity, obfuscatedTicketAge);
        }

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            return obj is PskIdentity that
                && m_obfuscatedTicketAge == that.m_obfuscatedTicketAge
                && Arrays.FixedTimeEquals(m_identity, that.m_identity);
        }

        /// <inheritdoc/>
        public override int GetHashCode() => Arrays.GetHashCode(m_identity) ^ m_obfuscatedTicketAge.GetHashCode();
    }
}
