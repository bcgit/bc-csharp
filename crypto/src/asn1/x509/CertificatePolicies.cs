using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks><code>CertificatePolicies ::= SEQUENCE SIZE {1..MAX} OF PolicyInformation</code></remarks>
    public class CertificatePolicies
        : Asn1Encodable
    {
        public static CertificatePolicies GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificatePolicies certificatePolicies)
                return certificatePolicies;
            return new CertificatePolicies(Asn1Sequence.GetInstance(obj));
        }

        public static CertificatePolicies GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new CertificatePolicies(Asn1Sequence.GetInstance(obj, isExplicit));

        public static CertificatePolicies GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificatePolicies(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static CertificatePolicies FromExtensions(X509Extensions extensions) =>
            GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.CertificatePolicies));

        // TODO[asn1] Tighten to DLSequence if/when safe
        private readonly DerSequence m_elements;

        private CertificatePolicies(Asn1Sequence seq)
        {
            if (seq.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(seq));

            m_elements = DerSequence.Map(seq, PolicyInformation.GetInstance);
        }

        /// <summary>Construct an instance containing a single <see cref="PolicyInformation"/>.</summary>
        public CertificatePolicies(PolicyInformation name)
        {
            m_elements = DerSequence.FromElement(name ?? throw new ArgumentNullException(nameof(name)));
        }

        public CertificatePolicies(PolicyInformation[] policyInformation)
        {
            if (Arrays.IsNullOrContainsNull(policyInformation))
                throw new ArgumentNullException(nameof(policyInformation), "cannot be null, or contain null");
            if (policyInformation.Length < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(policyInformation));

            m_elements = DerSequence.FromElements(policyInformation);
        }

        /// <summary>Return the <see cref="PolicyInformation"/>s making up the sequence.</summary>
        public virtual PolicyInformation[] GetPolicyInformation() =>
            m_elements.MapElements(PolicyInformation.GetInstance);

        public virtual PolicyInformation GetPolicyInformation(DerObjectIdentifier policyIdentifier)
        {
            // Elements are known to be PolicyInformation by construction
            foreach (PolicyInformation element in m_elements)
            {
                if (element.PolicyIdentifier.Equals(policyIdentifier))
                    return element;
            }
            return null;
        }

        public override Asn1Object ToAsn1Object() => m_elements;

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder("CertificatePolicies: ");
            sb.Append(m_elements[0]);
            for (int i = 1; i < m_elements.Count; ++i)
            {
                sb.Append(", ");
                sb.Append(m_elements[i]);
            }
            return sb.ToString();
        }
    }
}
