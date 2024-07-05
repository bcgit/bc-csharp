using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
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

        public static CertificatePolicies FromExtensions(X509Extensions extensions)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.CertificatePolicies));
        }

        private readonly PolicyInformation[] m_policyInformation;

        private CertificatePolicies(Asn1Sequence seq)
        {
            // TODO Enforce minimum length of 1?
            m_policyInformation = seq.MapElements(PolicyInformation.GetInstance);
        }

        /**
         * Construct a CertificatePolicies object containing one PolicyInformation.
         * 
         * @param name the name to be contained.
         */
        public CertificatePolicies(PolicyInformation name)
        {
            m_policyInformation = new PolicyInformation[]{
                name ?? throw new ArgumentNullException(nameof(name))
            };
        }

        public CertificatePolicies(PolicyInformation[] policyInformation)
        {
            if (Arrays.IsNullOrContainsNull(policyInformation))
                throw new NullReferenceException("'policyInformation' cannot be null, or contain null");

            m_policyInformation = Copy(policyInformation);
        }

        public virtual PolicyInformation[] GetPolicyInformation() => Copy(m_policyInformation);

        public virtual PolicyInformation GetPolicyInformation(DerObjectIdentifier policyIdentifier)
        {
            foreach (var policyInfo in m_policyInformation)
            {
                if (policyInfo.PolicyIdentifier.Equals(policyIdentifier))
                    return policyInfo;
            }
            return null;
        }

        /**
         * Produce an object suitable for an ASN1OutputStream.
         * <pre>
         * CertificatePolicies ::= SEQUENCE SIZE {1..MAX} OF PolicyInformation
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => DerSequence.FromElements(m_policyInformation);

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder("CertificatePolicies:");
            if (m_policyInformation.Length > 0)
            {
                sb.Append(' ');
                sb.Append(m_policyInformation[0]);
                for (int i = 1; i < m_policyInformation.Length; ++i)
                {
                    sb.Append(", ");
                    sb.Append(m_policyInformation[i]);
                }
            }
            return sb.ToString();
        }

        private static PolicyInformation[] Copy(PolicyInformation[] policyInformation) =>
            (PolicyInformation[])policyInformation.Clone();
    }
}
