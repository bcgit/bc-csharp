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
        private readonly Dictionary<SignerID, List<SignerInformation>> m_table =
            new Dictionary<SignerID, List<SignerInformation>>();

        /// <summary>
        /// Create a store containing a single SignerInformation object.
        /// </summary>
        /// <param name="signerInfo">The signer information to contain.</param>
        public SignerInformationStore(SignerInformation signerInfo)
        {
            m_all = new List<SignerInformation>(1){ signerInfo };
            m_table[signerInfo.SignerID] = m_all;
        }

        /// <summary>
        /// Create a store containing a collection of SignerInformation objects.
        /// </summary>
        /// <param name="signerInfos">A collection of signer information objects to contain.</param>
        public SignerInformationStore(IEnumerable<SignerInformation> signerInfos)
        {
            m_all = new List<SignerInformation>(signerInfos);

            foreach (SignerInformation signer in m_all)
            {
                SignerID sid = signer.SignerID;

                if (!m_table.TryGetValue(sid, out var list))
                {
                    list = new List<SignerInformation>(1);
                    m_table[sid] = list;
                }

                list.Add(signer);
            }
        }

        /// <summary>Gets the first signer matching the passed in selector, or null if there are no matches.</summary>
        /// <param name="selector">The signer ID to select against.</param>
        public SignerInformation this[SignerID selector] => GetFirstSigner(selector);

        /// <summary>
        /// Return the first <see cref="SignerInformation"/> object that matches the passed in selector.
        /// </summary>
        /// <param name="selector">The signer ID to select against.</param>
        /// <returns>A single <see cref="SignerInformation"/> object, or null if none matches.</returns>
        public SignerInformation GetFirstSigner(SignerID selector)
        {
            if (m_table.TryGetValue(selector, out var list))
                return list[0];

            return null;
        }

        /// <summary>The number of signers in the collection.</summary>
        public int Count => m_all.Count;

        /// <returns>A list of all signers in the collection</returns>
        public IList<SignerInformation> GetSigners() => new List<SignerInformation>(m_all);

        /// <summary>Return a (possibly empty) list of the signers matching the passed in selector.</summary>
        /// <param name="selector">The signer ID to select against.</param>
        /// <returns>A list of <see cref="SignerInformation"/> objects.</returns>
        public IList<SignerInformation> GetSigners(SignerID selector)
        {
            if (m_table.TryGetValue(selector, out var list))
                return new List<SignerInformation>(list);

            return new List<SignerInformation>(0);
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        /// <summary>Return an enumerator over all the signers in the store.</summary>
        public IEnumerator<SignerInformation> GetEnumerator()
        {
            IEnumerable<SignerInformation> e = CollectionUtilities.Proxy(m_all);
            return e.GetEnumerator();
        }

        internal List<SignerInformation> SignersInternal => m_all;
    }
}
