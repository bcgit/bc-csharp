using System;

using Org.BouncyCastle.Utilities;
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
