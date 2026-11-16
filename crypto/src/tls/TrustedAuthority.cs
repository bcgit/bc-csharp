using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>An entry of the trusted_ca_keys extension of RFC 6066.</summary>
    public sealed class TrustedAuthority
    {
        private readonly short m_identifierType;
        private readonly object m_identifier;

        /// <summary>Create a new <see cref="TrustedAuthority"/>.</summary>
        /// <param name="identifierType">The identifier type.</param>
        /// <param name="identifier">The identifier.</param>
        public TrustedAuthority(short identifierType, object identifier)
        {
            if (!IsCorrectType(identifierType, identifier))
                throw new ArgumentException("not an instance of the correct type", nameof(identifier));

            m_identifierType = identifierType;
            m_identifier = identifier;
        }

        /// <summary>Gets the identifier type.</summary>
        public short IdentifierType => m_identifierType;

        /// <summary>Gets the identifier.</summary>
        public object Identifier => m_identifier;

        /// <summary>Return the cert sha 1 hash.</summary>
        public byte[] GetCertSha1Hash() => Arrays.Clone((byte[])m_identifier);

        /// <summary>Return the key sha 1 hash.</summary>
        public byte[] GetKeySha1Hash() => Arrays.Clone((byte[])m_identifier);

        /// <summary>Gets the X.509 name of the authority, if the identifier type is X.509 name.</summary>
        public X509Name X509Name
        {
            get
            {
                CheckCorrectType(Tls.IdentifierType.x509_name);
                return (X509Name)m_identifier;
            }
        }

        /// <summary>Encode this <see cref="TrustedAuthority"/> to a <see cref="Stream"/>.</summary>
        /// <param name="output">the <see cref="Stream"/> to encode to.</param>
        /// <exception cref="IOException"/>
        public void Encode(Stream output)
        {
            TlsUtilities.WriteUint8(m_identifierType, output);

            switch (m_identifierType)
            {
            case Tls.IdentifierType.cert_sha1_hash:
            case Tls.IdentifierType.key_sha1_hash:
            {
                byte[] sha1Hash = (byte[])m_identifier;
                output.Write(sha1Hash, 0, sha1Hash.Length);
                break;
            }
            case Tls.IdentifierType.pre_agreed:
            {
                break;
            }
            case Tls.IdentifierType.x509_name:
            {
                X509Name dn = (X509Name)m_identifier;
                byte[] derEncoding = dn.GetEncoded(Asn1Encodable.Der);
                TlsUtilities.WriteOpaque16(derEncoding, output);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /// <summary>Parse a <see cref="TrustedAuthority"/> from a <see cref="Stream"/>.</summary>
        /// <param name="input">the <see cref="Stream"/> to parse from.</param>
        /// <returns>a <see cref="TrustedAuthority"/> object.</returns>
        /// <exception cref="IOException"/>
        public static TrustedAuthority Parse(Stream input)
        {
            short identifier_type = TlsUtilities.ReadUint8(input);
            object identifier;

            switch (identifier_type)
            {
            case Tls.IdentifierType.cert_sha1_hash:
            case Tls.IdentifierType.key_sha1_hash:
            {
                identifier = TlsUtilities.ReadFully(20, input);
                break;
            }
            case Tls.IdentifierType.pre_agreed:
            {
                identifier = null;
                break;
            }
            case Tls.IdentifierType.x509_name:
            {
                byte[] derEncoding = TlsUtilities.ReadOpaque16(input, 1);
                identifier = TlsUtilities.ReadDerEncoding(derEncoding, X509Name.GetOptional);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            return new TrustedAuthority(identifier_type, identifier);
        }

        private void CheckCorrectType(short expectedIdentifierType)
        {
            if (m_identifierType != expectedIdentifierType || !IsCorrectType(expectedIdentifierType, m_identifier))
                throw new InvalidOperationException("TrustedAuthority is not of type "
                    + Tls.IdentifierType.GetName(expectedIdentifierType));
        }

        private static bool IsCorrectType(short identifierType, object identifier)
        {
            switch (identifierType)
            {
            case Tls.IdentifierType.cert_sha1_hash:
            case Tls.IdentifierType.key_sha1_hash:
                return IsSha1Hash(identifier);
            case Tls.IdentifierType.pre_agreed:
                return identifier == null;
            case Tls.IdentifierType.x509_name:
                return identifier is X509Name;
            default:
                throw new ArgumentException("unsupported IdentifierType", nameof(identifierType));
            }
        }

        private static bool IsSha1Hash(object identifier) => identifier is byte[] bytes && bytes.Length == 20;
    }
}
