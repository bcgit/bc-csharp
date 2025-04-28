using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Cms
{
    public class RecipientInformationStore
        : IEnumerable<RecipientInformation>
    {
        private readonly List<RecipientInformation> m_all;
        private readonly Dictionary<RecipientID, List<RecipientInformation>> m_table =
            new Dictionary<RecipientID, List<RecipientInformation>>();

        /**
         * Create a store containing a single RecipientInformation object.
         *
         * @param recipientInfo the recipient information to contain.
         */
        public RecipientInformationStore(RecipientInformation recipientInfo)
        {
            m_all = new List<RecipientInformation>(1){ recipientInfo };
            m_table[recipientInfo.RecipientID] = m_all;
        }

        /**
         * Create a store containing a collection of RecipientInformation objects.
         *
         * @param recipientInfos a collection of recipient information objects to contain.
         */
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

        public RecipientInformation this[RecipientID selector] => GetFirstRecipient(selector);

        /**
         * Return the first RecipientInformation object that matches the
         * passed in selector. Null if there are no matches.
         *
         * @param selector to identify a recipient
         * @return a single RecipientInformation object. Null if none matches.
         */
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

        /**
         * Return possible empty collection with recipients matching the passed in RecipientID
         *
         * @param selector a recipient id to select against.
         * @return a collection of RecipientInformation objects.
         */
        public IList<RecipientInformation> GetRecipients(RecipientID selector)
        {
            if (!m_table.TryGetValue(selector, out var list))
                return new List<RecipientInformation>(0);

            return new List<RecipientInformation>(list);
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        public IEnumerator<RecipientInformation> GetEnumerator()
        {
            IEnumerable<RecipientInformation> e = CollectionUtilities.Proxy(m_all);
            return e.GetEnumerator();
        }

        internal List<RecipientInformation> RecipientsInternal => m_all;
    }
}
