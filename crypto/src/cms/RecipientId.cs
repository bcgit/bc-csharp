using System;

using Org.BouncyCastle.Utilities;
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
