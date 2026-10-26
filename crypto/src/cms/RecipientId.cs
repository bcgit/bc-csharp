using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Identifies a CMS recipient by issuer and serial number, subject key identifier, or KEK key identifier.
    /// </summary>
    // TODO[api] sealed
    public class RecipientID
        : X509CertStoreSelector, IEquatable<RecipientID>
    {
        /// <summary>
        /// Create an identifier for the recipient associated with <paramref name="certificate"/>.
        /// </summary>
        /// <remarks>
        /// The identifier carries the certificate's issuer and serial number and, when the certificate has a
        /// subject key identifier extension, its subject key identifier as well. A
        /// <see cref="RecipientInformationStore"/> looks it up as matching a recipient that identifies the certificate
        /// in either way, returning recipients identified by issuer and serial number first. As a certificate selector
        /// it matches <paramref name="certificate"/>.
        /// </remarks>
        /// <param name="certificate">The recipient's certificate.</param>
        /// <returns>
        /// A <see cref="RecipientID"/> selecting recipients that identify <paramref name="certificate"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">If <paramref name="certificate"/> is <c>null</c>.</exception>
        public static RecipientID ForCertificate(X509Certificate certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            return new RecipientID()
            {
                Issuer = certificate.IssuerDN,
                SerialNumber = certificate.SerialNumber,
                SubjectKeyIdentifier = certificate.GetExtensionValue(X509Extensions.SubjectKeyIdentifier)?.GetOctets(),
            };
        }

        private byte[] m_keyIdentifier;

        /// <summary>Gets or sets the recipient key identifier.</summary>
        public byte[] KeyIdentifier
        {
            get { return Arrays.Clone(m_keyIdentifier); }
            set { m_keyIdentifier = Arrays.Clone(value); }
        }

        /// <summary>Determines whether this identifier selects the same recipient as <paramref name="other"/>.
        /// </summary>
        /// <param name="other">The identifier to compare.</param>
        /// <returns><c>true</c> if the identifiers match; otherwise, <c>false</c>.</returns>
        public virtual bool Equals(RecipientID other)
        {
            return other == null ? false
                :  other == this ? true
                :  Arrays.AreEqual(m_keyIdentifier, other.m_keyIdentifier)
                && MatchesSubjectKeyIdentifier(other)
                && MatchesSerialNumber(other)
                && MatchesIssuer(other);
        }

        /// <inheritdoc/>
        public override bool Equals(object obj) => Equals(obj as RecipientID);

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return Arrays.GetHashCode(m_keyIdentifier)
                ^  GetHashCodeOfSubjectKeyIdentifier()
                ^  Objects.GetHashCode(SerialNumber)
                ^  Objects.GetHashCode(Issuer);
        }
    }
}
