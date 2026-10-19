using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks><code>CertificatePolicies ::= SEQUENCE SIZE {1..MAX} OF PolicyInformation</code></remarks>
    public class CertificatePolicies
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertificatePolicies"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertificatePolicies"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertificatePolicies"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertificatePolicies GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificatePolicies certificatePolicies)
                return certificatePolicies;
            return new CertificatePolicies(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertificatePolicies"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificatePolicies"/>.</returns>
        public static CertificatePolicies GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new CertificatePolicies(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="CertificatePolicies"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificatePolicies"/>.</returns>
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

        /// <summary>Create a new <see cref="CertificatePolicies"/>.</summary>
        /// <param name="policyInformation">The policy information.</param>
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

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_elements;

        /// <inheritdoc/>
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
