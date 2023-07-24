using System.Collections.Generic;

namespace Org.BouncyCastle.Cms
{
    public class SignerInformationStore
        : IEnumerable<SignerInformation>
    {
        private readonly IList<SignerInformation> m_all;
        private readonly IDictionary<SignerID, IList<SignerInformation>> m_table =
            new Dictionary<SignerID, IList<SignerInformation>>();

        /**
         * Create a store containing a single SignerInformation object.
         *
         * @param signerInfo the signer information to contain.
         */
        public SignerInformationStore(SignerInformation signerInfo)
        {
            m_all = new List<SignerInformation>(1);
            m_all.Add(signerInfo);

            SignerID sid = signerInfo.SignerID;

            m_table[sid] = m_all;
        }

        /**
         * Create a store containing a collection of SignerInformation objects.
         *
         * @param signerInfos a collection signer information objects to contain.
         */
        public SignerInformationStore(IEnumerable<SignerInformation> signerInfos)
        {
            m_all = new List<SignerInformation>(signerInfos);

            foreach (SignerInformation signer in signerInfos)
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

        /**
        * Return the first SignerInformation object that matches the
        * passed in selector. Null if there are no matches.
        *
        * @param selector to identify a signer
        * @return a single SignerInformation object. Null if none matches.
        */
        public SignerInformation GetFirstSigner(SignerID selector)
        {
            if (m_table.TryGetValue(selector, out var list))
                return list[0];

            return null;
        }

        /// <summary>The number of signers in the collection.</summary>
        public int Count => m_all.Count;

        /// <returns>An ICollection of all signers in the collection</returns>
        public IList<SignerInformation> GetSigners() => new List<SignerInformation>(m_all);

        /**
        * Return possible empty collection with signers matching the passed in SignerID
        *
        * @param selector a signer id to select against.
        * @return a collection of SignerInformation objects.
        */
        public IList<SignerInformation> GetSigners(SignerID selector)
        {
            if (m_table.TryGetValue(selector, out var list))
                return new List<SignerInformation>(list);

            return new List<SignerInformation>(0);
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        public IEnumerator<SignerInformation> GetEnumerator() => GetSigners().GetEnumerator();
    }
}
