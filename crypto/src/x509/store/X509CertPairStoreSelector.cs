using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.X509.Store
{
    /// <remarks>
    /// This class is an <code>IX509Selector</code> implementation to select
    /// certificate pairs, which are e.g. used for cross certificates. The set of
    /// criteria is given from two <code>X509CertStoreSelector</code> objects,
    /// each of which, if present, must match the respective component of a pair.
    /// </remarks>
    public class X509CertPairStoreSelector
        : ISelector<X509CertificatePair>
    {
        private static X509CertStoreSelector CloneSelector(X509CertStoreSelector s) =>
            (X509CertStoreSelector)s?.Clone();

        private X509CertificatePair m_certPair;
        private X509CertStoreSelector m_forwardSelector;
        private X509CertStoreSelector m_reverseSelector;

        public X509CertPairStoreSelector()
        {
        }

        private X509CertPairStoreSelector(X509CertPairStoreSelector o)
        {
            m_certPair = o.CertPair;
            m_forwardSelector = o.ForwardSelector;
            m_reverseSelector = o.ReverseSelector;
        }

        /// <summary>The certificate pair which is used for testing on equality.</summary>
        public X509CertificatePair CertPair
        {
            get { return m_certPair; }
            set { m_certPair = value; }
        }

        /// <summary>The certificate selector for the forward part.</summary>
        public X509CertStoreSelector ForwardSelector
        {
            get { return CloneSelector(m_forwardSelector); }
            set { m_forwardSelector = CloneSelector(value); }
        }

        /// <summary>The certificate selector for the reverse part.</summary>
        public X509CertStoreSelector ReverseSelector
        {
            get { return CloneSelector(m_reverseSelector); }
            set { m_reverseSelector = CloneSelector(value); }
        }

        /// <summary>
        /// Decides if the given certificate pair should be selected. If
        /// <c>obj</c> is not a <code>X509CertificatePair</code>, this method
        /// returns <code>false</code>.
        /// </summary>
        /// <param name="pair">The <code>X509CertificatePair</code> to be tested.</param>
        /// <returns><code>true</code> if the object matches this selector.</returns>
        public bool Match(X509CertificatePair pair)
        {
            if (pair == null)
                return false;

            if (m_certPair != null && !m_certPair.Equals(pair))
                return false;

            if (m_forwardSelector != null && !m_forwardSelector.Match(pair.Forward))
                return false;

            if (m_reverseSelector != null && !m_reverseSelector.Match(pair.Reverse))
                return false;

            return true;
        }

        public object Clone() => new X509CertPairStoreSelector(this);
    }
}
