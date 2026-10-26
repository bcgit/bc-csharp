using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Identifies a CMS signer by issuer and serial number or subject key identifier.
    /// </summary>
    // TODO[api] sealed
    public class SignerID
        : X509CertStoreSelector, IEquatable<SignerID>
    {
        /// <summary>
        /// Create an identifier for the signer associated with <paramref name="certificate"/>.
        /// </summary>
        /// <remarks>
        /// The identifier carries the certificate's issuer and serial number and, when the certificate has a
        /// subject key identifier extension, its subject key identifier as well. A
        /// <see cref="SignerInformationStore"/> looks it up as matching a signer that identifies the certificate in
        /// either way, returning signers identified by issuer and serial number first. As a certificate selector it
        /// matches <paramref name="certificate"/>.
        /// </remarks>
        /// <param name="certificate">The signer's certificate.</param>
        /// <returns>A <see cref="SignerID"/> selecting signers that identify <paramref name="certificate"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="certificate"/> is <c>null</c>.</exception>
        public static SignerID ForCertificate(X509Certificate certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            return new SignerID()
            {
                Issuer = certificate.IssuerDN,
                SerialNumber = certificate.SerialNumber,
                SubjectKeyIdentifier = certificate.GetExtensionValue(X509Extensions.SubjectKeyIdentifier)?.GetOctets(),
            };
        }

        /// <summary>Determines whether this identifier selects the same signer as <paramref name="other"/>.
        /// </summary>
        /// <param name="other">The identifier to compare.</param>
        /// <returns><c>true</c> if the identifiers match; otherwise, <c>false</c>.</returns>
        public virtual bool Equals(SignerID other)
        {
            return other == null ? false
                :  other == this ? true
                :  MatchesSubjectKeyIdentifier(other)
                && MatchesSerialNumber(other)
                && MatchesIssuer(other);
        }

        /// <inheritdoc/>
        public override bool Equals(object obj) => Equals(obj as SignerID);

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return GetHashCodeOfSubjectKeyIdentifier()
                ^  Objects.GetHashCode(SerialNumber)
                ^  Objects.GetHashCode(Issuer);
        }
    }
}
