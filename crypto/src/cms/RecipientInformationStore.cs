using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// A store collection class for RecipientInformation objects.
    /// </summary>
    public class RecipientInformationStore
        : IEnumerable<RecipientInformation>
    {
        private readonly List<RecipientInformation> m_all;

        /// <summary>
        /// Create a store containing a single RecipientInformation object.
        /// </summary>
        /// <param name="recipientInfo">The recipient information to contain.</param>
        public RecipientInformationStore(RecipientInformation recipientInfo)
        {
            m_all = new List<RecipientInformation>(1){ recipientInfo };
        }

        /// <summary>
        /// Create a store containing a collection of RecipientInformation objects.
        /// </summary>
        /// <param name="recipientInfos">A collection of recipient information objects to contain.</param>
        public RecipientInformationStore(IEnumerable<RecipientInformation> recipientInfos)
        {
            m_all = new List<RecipientInformation>(recipientInfos);
        }

        public RecipientInformation this[RecipientID selector] => GetFirstRecipient(selector);

        /// <summary>
        /// Return the first recipient object that matches the passed in <see cref="RecipientID"/>, or <c>null</c>.
        /// </summary>
        /// <param name="selector">A <see cref="RecipientID"/> to select against.</param>
        /// <returns>A single <see cref="RecipientInformation"/> object, or <c>null</c> if none matches.</returns>
        public RecipientInformation GetFirstRecipient(RecipientID selector)
        {
            if (selector.Issuer != null && selector.SubjectKeyIdentifierInternal != null)
            {
                return CollectionUtilities.GetFirstOrNull(MatchingRecipients(WithIssuerAndSerialNumber(selector)))
                    ?? CollectionUtilities.GetFirstOrNull(MatchingRecipients(WithSubjectKeyIdentifier(selector)));
            }
            else
            {
                return CollectionUtilities.GetFirstOrNull(MatchingRecipients(selector));
            }
        }

        /// <summary>The number of recipients in the collection.</summary>
        public int Count => m_all.Count;

        /// <returns>A list of all recipients in the collection</returns>
        public IList<RecipientInformation> GetRecipients() => new List<RecipientInformation>(m_all);

        /// <summary>
        /// Return a possibly empty list of recipients matching the passed in <see cref="RecipientID"/>.
        /// </summary>
        /// <param name="selector">A <see cref="RecipientID"/> to select against.</param>
        /// <returns>A list of <see cref="RecipientInformation"/> objects.</returns>
        public IList<RecipientInformation> GetRecipients(RecipientID selector)
        {
            // A message carries a handful of recipients: a scan costs no more than a hash lookup and,
            // unlike a Dictionary keyed on the recipient IDs, cannot be flooded by IDs chosen to collide.

            List<RecipientInformation> results = new List<RecipientInformation>(0);

            if (selector.Issuer != null && selector.SubjectKeyIdentifierInternal != null)
            {
                results.AddRange(MatchingRecipients(WithIssuerAndSerialNumber(selector)));
                results.AddRange(MatchingRecipients(WithSubjectKeyIdentifier(selector)));
            }
            else
            {
                results.AddRange(MatchingRecipients(selector));
            }

            return results;
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        public IEnumerator<RecipientInformation> GetEnumerator()
        {
            IEnumerable<RecipientInformation> e = CollectionUtilities.Proxy(m_all);
            return e.GetEnumerator();
        }

        internal List<RecipientInformation> RecipientsInternal => m_all;

        private IEnumerable<RecipientInformation> MatchingRecipients(RecipientID selector) =>
            CollectionUtilities.Where(m_all, recipient => selector.Equals(recipient.RecipientID));

        private static RecipientID WithIssuerAndSerialNumber(RecipientID selector) =>
            new RecipientID()
            {
                Issuer = selector.Issuer,
                SerialNumber = selector.SerialNumber,
            };

        private static RecipientID WithSubjectKeyIdentifier(RecipientID selector) =>
            new RecipientID()
            {
                SubjectKeyIdentifierInternal = selector.SubjectKeyIdentifierInternal,
            };
    }
}
