using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Cms
{
    /// <summary>A collection of <see cref="RecipientInformation"/> objects, indexed by recipient ID.</summary>
    public class RecipientInformationStore
        : IEnumerable<RecipientInformation>
    {
        private readonly List<RecipientInformation> m_all;
        private readonly Dictionary<RecipientID, List<RecipientInformation>> m_table =
            new Dictionary<RecipientID, List<RecipientInformation>>();

        /// <summary>Create a store containing a single <see cref="RecipientInformation"/> object.</summary>
        /// <param name="recipientInfo">The recipient information to contain.</param>
        public RecipientInformationStore(RecipientInformation recipientInfo)
        {
            m_all = new List<RecipientInformation>(1){ recipientInfo };
            m_table[recipientInfo.RecipientID] = m_all;
        }

        /// <summary>Create a store containing a collection of <see cref="RecipientInformation"/> objects.</summary>
        /// <param name="recipientInfos">A collection of recipient information objects to contain.</param>
        public RecipientInformationStore(IEnumerable<RecipientInformation> recipientInfos)
        {
            m_all = new List<RecipientInformation>(recipientInfos);

            foreach (RecipientInformation recipientInformation in m_all)
            {
                RecipientID rid = recipientInformation.RecipientID;

                if (!m_table.TryGetValue(rid, out var list))
                {
                    m_table[rid] = list = new List<RecipientInformation>(1);
                }

                list.Add(recipientInformation);
            }
        }

        /// <summary>
        /// Gets the first recipient matching the passed in selector, or null if there are no matches.
        /// </summary>
        /// <param name="selector">The recipient ID to select against.</param>
        public RecipientInformation this[RecipientID selector] => GetFirstRecipient(selector);

        /// <summary>
        /// Return the first <see cref="RecipientInformation"/> object that matches the passed in selector.
        /// </summary>
        /// <param name="selector">The recipient ID to select against.</param>
        /// <returns>A single <see cref="RecipientInformation"/> object, or null if none matches.</returns>
        public RecipientInformation GetFirstRecipient(RecipientID selector)
        {
            if (!m_table.TryGetValue(selector, out var list))
                return null;

            return list[0];
        }

        /// <summary>The number of recipients in the collection.</summary>
        public int Count => m_all.Count;

        /// <returns>A list of all recipients in the collection</returns>
        public IList<RecipientInformation> GetRecipients() => new List<RecipientInformation>(m_all);

        /// <summary>Return a (possibly empty) list of the recipients matching the passed in selector.</summary>
        /// <param name="selector">The recipient ID to select against.</param>
        /// <returns>A list of <see cref="RecipientInformation"/> objects.</returns>
        public IList<RecipientInformation> GetRecipients(RecipientID selector)
        {
            if (!m_table.TryGetValue(selector, out var list))
                return new List<RecipientInformation>(0);

            return new List<RecipientInformation>(list);
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        /// <summary>Return an enumerator over all the recipients in the store.</summary>
        public IEnumerator<RecipientInformation> GetEnumerator()
        {
            IEnumerable<RecipientInformation> e = CollectionUtilities.Proxy(m_all);
            return e.GetEnumerator();
        }

        internal List<RecipientInformation> RecipientsInternal => m_all;
    }
}
