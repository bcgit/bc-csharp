using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The AuthorityKeyIdentifier object.</summary>
    /// <remarks>
    /// <code>
    /// id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
    ///
    /// AuthorityKeyIdentifier ::= Sequence {
    ///     keyIdentifier[0] IMPLICIT KeyIdentifier                         OPTIONAL,
    ///     authorityCertIssuer[1] IMPLICIT GeneralNames                    OPTIONAL,
    ///     authorityCertSerialNumber[2] IMPLICIT CertificateSerialNumber   OPTIONAL
    /// }
    ///
    /// KeyIdentifier ::= OCTET STRING
    /// </code>
    /// Per RFC 5280 sec. 4.2.1.1 the authorityCertIssuer and authorityCertSerialNumber fields MUST both be present or
    /// both be absent.
    /// </remarks>
    public class AuthorityKeyIdentifier
        : Asn1Encodable
    {
        public static AuthorityKeyIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthorityKeyIdentifier authorityKeyIdentifier)
                return authorityKeyIdentifier;
            // TODO[api] Remove this case
            if (obj is X509Extension x509Extension)
                return GetInstance(X509Extension.ConvertValueToObject(x509Extension));
#pragma warning disable CS0618 // Type or member is obsolete
            return new AuthorityKeyIdentifier(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static AuthorityKeyIdentifier GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new AuthorityKeyIdentifier(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static AuthorityKeyIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new AuthorityKeyIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static AuthorityKeyIdentifier FromExtensions(X509Extensions extensions) =>
            GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.AuthorityKeyIdentifier));

        private readonly Asn1OctetString m_keyIdentifier;
        private readonly GeneralNames m_authorityCertIssuer;
        private readonly DerInteger m_authorityCertSerialNumber;

        [Obsolete("Use 'GetInstance' instead")]
        protected internal AuthorityKeyIdentifier(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            var keyIdentifier = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false,
                Asn1OctetString.GetTagged);
            var authorityCertIssuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false,
                GeneralNames.GetTagged);
            var authorityCertSerialNumber = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false,
                DerInteger.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            CheckIssuerAndSerial(authorityCertIssuer, authorityCertSerialNumber);

            m_keyIdentifier = keyIdentifier;
            m_authorityCertIssuer = authorityCertIssuer;
            m_authorityCertSerialNumber = authorityCertSerialNumber;
        }

        /// <summary>
        /// Calculates the keyIdentifier using a SHA1 hash over the BIT STRING from SubjectPublicKeyInfo as defined in RFC2459.
        /// </summary>
        [Obsolete("Use 'X509ExtensionUtilities' methods instead")]
        public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki)
            : this(spki, null, null)
        {
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier with the GeneralNames tag and the serial number provided as well.
        /// </summary>
        [Obsolete("Use 'X509ExtensionUtilities' methods instead")]
        public AuthorityKeyIdentifier(SubjectPublicKeyInfo spki, GeneralNames name, BigInteger serialNumber)
            : this(
                // TODO[api] This ASN.1 class is the wrong place for this calculation
                DigestUtilities.CalculateDigest(OiwObjectIdentifiers.IdSha1, spki.PublicKey.GetBytes()),
                name,
                serialNumber)
        {
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier with the GeneralNames tag and the serial number provided.
        /// </summary>
        // TODO[api] Rename parameters
        public AuthorityKeyIdentifier(GeneralNames name, BigInteger serialNumber)
            : this((byte[])null, name, serialNumber)
        {
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier with a precomputed key identifier
        /// </summary>
        public AuthorityKeyIdentifier(byte[] keyIdentifier)
            : this(keyIdentifier, null, null)
        {
        }

        /// <summary>
        /// Create an AuthorityKeyIdentifier with a precomputed key identifier and the GeneralNames tag and the serial
        /// number provided as well.
        /// </summary>
        // TODO[api] Rename parameters
        public AuthorityKeyIdentifier(byte[] keyIdentifier, GeneralNames name, BigInteger serialNumber)
        {
            var authorityCertSerialNumber = serialNumber == null ? null : new DerInteger(serialNumber);
            CheckIssuerAndSerial(name, authorityCertSerialNumber);

            m_keyIdentifier = DerOctetString.FromContentsOptional(keyIdentifier);
            m_authorityCertIssuer = name;
            m_authorityCertSerialNumber = authorityCertSerialNumber;
        }

        public AuthorityKeyIdentifier(Asn1OctetString keyIdentifier)
            : this(keyIdentifier, authorityCertIssuer: null, authorityCertSerialNumber: null)
        {
        }

        public AuthorityKeyIdentifier(Asn1OctetString keyIdentifier, GeneralNames authorityCertIssuer,
            DerInteger authorityCertSerialNumber)
        {
            CheckIssuerAndSerial(authorityCertIssuer, authorityCertSerialNumber);

            m_keyIdentifier = keyIdentifier;
            m_authorityCertIssuer = authorityCertIssuer;
            m_authorityCertSerialNumber = authorityCertSerialNumber;
        }

        [Obsolete("Use 'KeyIdentifier' instead")]
        public byte[] GetKeyIdentifier() => m_keyIdentifier?.GetOctets();

        public GeneralNames AuthorityCertIssuer => m_authorityCertIssuer;

        public BigInteger AuthorityCertSerialNumber => m_authorityCertSerialNumber?.Value;

        public Asn1OctetString KeyIdentifier => m_keyIdentifier;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(false, 0, m_keyIdentifier);
            v.AddOptionalTagged(false, 1, m_authorityCertIssuer);
            v.AddOptionalTagged(false, 2, m_authorityCertSerialNumber);
            return new DerSequence(v);
        }

        public override string ToString()
        {
            string keyID = m_keyIdentifier == null
                ? "null"
                : Hex.ToHexString(m_keyIdentifier.GetOctets());

            return "AuthorityKeyIdentifier: KeyID(" + keyID + ")";
        }

        /// <summary>
        /// RFC 5280 sec. 4.2.1.1: authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be
        /// absent.
        /// </summary>
        private static void CheckIssuerAndSerial(GeneralNames certIssuer, DerInteger certSerial)
        {
            if (certIssuer == null ^ certSerial == null)
            {
                throw new ArgumentException(
                    "AuthorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent");
            }
        }
    }
}
