using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.X509.Extension
{
    /// <remarks>A high level authority key identifier.</remarks>
    [Obsolete("Use 'X509ExtensionUtilities' methods instead")]
    public class AuthorityKeyIdentifierStructure
		: AuthorityKeyIdentifier
	{
		public AuthorityKeyIdentifierStructure(Asn1OctetString encodedValue)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(Asn1Sequence.GetInstance(encodedValue.GetOctets()))
#pragma warning restore CS0618 // Type or member is obsolete
        {
        }

        /**
		 * Create an AuthorityKeyIdentifier using the passed in certificate's public
		 * key, issuer and serial number.
		 *
		 * @param certificate the certificate providing the information.
		 * @throws CertificateParsingException if there is a problem processing the certificate
		 */
        public AuthorityKeyIdentifierStructure(X509Certificate certificate)
            : base(
                keyIdentifier: X509ExtensionUtilities.DeriveAuthCertKeyID(certificate),
                authorityCertIssuer: new GeneralNames(new GeneralName(certificate.IssuerDN)),
                authorityCertSerialNumber: certificate.CertificateStructure.SerialNumber)
        {
        }

        /**
		 * Create an AuthorityKeyIdentifier using just the hash of the
		 * public key.
		 *
		 * @param pubKey the key to generate the hash from.
		 * @throws InvalidKeyException if there is a problem using the key.
		 */
        public AuthorityKeyIdentifierStructure(AsymmetricKeyParameter pubKey)
			: base(keyIdentifier: X509ExtensionUtilities.CalculateKeyIdentifier(pubKey))
        {
        }
    }
}
