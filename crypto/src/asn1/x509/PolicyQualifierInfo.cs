using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * Policy qualifiers, used in the X509V3 CertificatePolicies
     * extension.
     *
     * <pre>
     *   PolicyQualifierInfo ::= Sequence {
     *       policyQualifierId  PolicyQualifierId,
     *       qualifier          ANY DEFINED BY policyQualifierId }
     * </pre>
     */
    public class PolicyQualifierInfo
        : Asn1Encodable
    {
        public static PolicyQualifierInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PolicyQualifierInfo policyQualifierInfo)
                return policyQualifierInfo;
            return new PolicyQualifierInfo(Asn1Sequence.GetInstance(obj));
        }

        public static PolicyQualifierInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PolicyQualifierInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PolicyQualifierInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PolicyQualifierInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_policyQualifierId;
        private readonly Asn1Encodable m_qualifier;

        /**
         * Creates a new <code>PolicyQualifierInfo</code> instance.
         *
         * @param as <code>PolicyQualifierInfo</code> X509 structure
         * encoded as an Asn1Sequence.
         */
        private PolicyQualifierInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_policyQualifierId = DerObjectIdentifier.GetInstance(seq[0]);
            m_qualifier = seq[1];
        }

        /**
         * Creates a new <code>PolicyQualifierInfo</code> instance.
         *
         * @param policyQualifierId a <code>PolicyQualifierId</code> value
         * @param qualifier the qualifier, defined by the above field.
         */
        public PolicyQualifierInfo(DerObjectIdentifier policyQualifierId, Asn1Encodable qualifier)
        {
            m_policyQualifierId = policyQualifierId ?? throw new ArgumentNullException(nameof(policyQualifierId));
            m_qualifier = qualifier ?? throw new ArgumentNullException(nameof(qualifier));
        }

        /**
         * Creates a new <code>PolicyQualifierInfo</code> containing a
         * cPSuri qualifier.
         *
         * @param cps the CPS (certification practice statement) uri as a
         * <code>string</code>.
         */
        public PolicyQualifierInfo(string cps)
        {
            m_policyQualifierId = PolicyQualifierID.IdQtCps;
            m_qualifier = new DerIA5String(cps);
        }

        public virtual DerObjectIdentifier PolicyQualifierId => m_policyQualifierId;

        public virtual Asn1Encodable Qualifier => m_qualifier;

        /**
         * Returns a Der-encodable representation of this instance.
         *
         * @return a <code>Asn1Object</code> value
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_policyQualifierId, m_qualifier);
    }
}
