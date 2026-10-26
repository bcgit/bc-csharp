using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// A store collection class for SignerInformation objects.
    /// </summary>
    public class SignerInformationStore
        : IEnumerable<SignerInformation>
    {
        private readonly List<SignerInformation> m_all;

        /// <summary>
        /// Create a store containing a single SignerInformation object.
        /// </summary>
        /// <param name="signerInfo">The signer information to contain.</param>
        public SignerInformationStore(SignerInformation signerInfo)
        {
            m_all = new List<SignerInformation>(1){ signerInfo };
        }

        /// <summary>
        /// Create a store containing a collection of SignerInformation objects.
        /// </summary>
        /// <param name="signerInfos">A collection of signer information objects to contain.</param>
        public SignerInformationStore(IEnumerable<SignerInformation> signerInfos)
        {
            m_all = new List<SignerInformation>(signerInfos);
        }

        public SignerInformation this[SignerID selector] => GetFirstSigner(selector);

        /// <summary>
        /// Return the first signer object that matches the passed in <see cref="SignerID"/>, or <c>null</c>.
        /// </summary>
        /// <param name="selector">A <see cref="SignerID"/> to select against.</param>
        /// <returns>A single <see cref="SignerInformation"/> object, or <c>null</c> if none matches.</returns>
        public SignerInformation GetFirstSigner(SignerID selector)
        {
            if (selector.Issuer != null && selector.SubjectKeyIdentifierInternal != null)
            {
                return CollectionUtilities.GetFirstOrNull(MatchingSigners(WithIssuerAndSerialNumber(selector)))
                    ?? CollectionUtilities.GetFirstOrNull(MatchingSigners(WithSubjectKeyIdentifier(selector)));
            }
            else
            {
                return CollectionUtilities.GetFirstOrNull(MatchingSigners(selector));
            }
        }

        /// <summary>The number of signers in the collection.</summary>
        public int Count => m_all.Count;

        /// <returns>A list of all signers in the collection</returns>
        public IList<SignerInformation> GetSigners() => new List<SignerInformation>(m_all);

        /// <summary>
        /// Return a possibly empty list of signers matching the passed in <see cref="SignerID"/>.
        /// </summary>
        /// <param name="selector">A <see cref="SignerID"/> to select against.</param>
        /// <returns>A list of <see cref="SignerInformation"/> objects.</returns>
        public IList<SignerInformation> GetSigners(SignerID selector)
        {
            // A message carries a handful of signers: a scan costs no more than a hash lookup and,
            // unlike a Dictionary keyed on the signer IDs, cannot be flooded by IDs chosen to collide.

            List<SignerInformation> results = new List<SignerInformation>(0);

            if (selector.Issuer != null && selector.SubjectKeyIdentifierInternal != null)
            {
                results.AddRange(MatchingSigners(WithIssuerAndSerialNumber(selector)));
                results.AddRange(MatchingSigners(WithSubjectKeyIdentifier(selector)));
            }
            else
            {
                results.AddRange(MatchingSigners(selector));
            }

            return results;
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        public IEnumerator<SignerInformation> GetEnumerator()
        {
            IEnumerable<SignerInformation> e = CollectionUtilities.Proxy(m_all);
            return e.GetEnumerator();
        }

        internal List<SignerInformation> SignersInternal => m_all;

        private IEnumerable<SignerInformation> MatchingSigners(SignerID selector) =>
            CollectionUtilities.Where(m_all, signer => selector.Equals(signer.SignerID));

        private static SignerID WithIssuerAndSerialNumber(SignerID selector) =>
            new SignerID()
            {
                Issuer = selector.Issuer,
                SerialNumber = selector.SerialNumber,
            };

        private static SignerID WithSubjectKeyIdentifier(SignerID selector) =>
            new SignerID()
            {
                SubjectKeyIdentifierInternal = selector.SubjectKeyIdentifierInternal,
            };
    }
}
