using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * PolicyMappings V3 extension, described in RFC3280.
     * <pre>
     *   PolicyMappings ::= Sequence SIZE (1..MAX) OF Sequence {
     *     issuerDomainPolicy   CertPolicyId,
     *     subjectDomainPolicy  CertPolicyId }
     *
     *   CertPolicyId ::= OBJECT IDENTIFIER
     * </pre>
     *
     * @see <a href="http://www.faqs.org/rfc/rfc3280.txt">RFC 3280, section 4.2.1.6</a>
     */
    public class PolicyMappings
        : Asn1Encodable
    {
        public class Element
            : Asn1Encodable
        {
            public static Element GetInstance(object obj)
            {
                if (obj == null)
                    return null;
                if (obj is Element element)
                    return element;
                return new Element(Asn1Sequence.GetInstance(obj));
            }

            public static Element GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
                new Element(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

            private readonly DerObjectIdentifier m_issuerDomainPolicy;
            private readonly DerObjectIdentifier m_subjectDomainPolicy;

            private Element(Asn1Sequence seq)
            {
                int count = seq.Count;
                if (count != 2)
                    throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

                m_issuerDomainPolicy = DerObjectIdentifier.GetInstance(seq[0]);
                m_subjectDomainPolicy = DerObjectIdentifier.GetInstance(seq[1]);
            }

            public Element(DerObjectIdentifier issuerDomainPolicy, DerObjectIdentifier subjectDomainPolicy)
            {
                m_issuerDomainPolicy = issuerDomainPolicy ?? throw new ArgumentNullException(nameof(issuerDomainPolicy));
                m_subjectDomainPolicy = subjectDomainPolicy ?? throw new ArgumentNullException(nameof(subjectDomainPolicy));
            }

            public DerObjectIdentifier IssuerDomainPolicy => m_issuerDomainPolicy;

            public DerObjectIdentifier SubjectDomainPolicy => m_subjectDomainPolicy;

            public override Asn1Object ToAsn1Object() => new DLSequence(m_issuerDomainPolicy, m_subjectDomainPolicy);
        }

        public static PolicyMappings GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PolicyMappings policyMappings)
                return policyMappings;
#pragma warning disable CS0618 // Type or member is obsolete
            return new PolicyMappings(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static PolicyMappings GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PolicyMappings(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Sequence m_elements;

        /**
         * Creates a new <code>PolicyMappings</code> instance.
         *
         * @param seq an <code>Asn1Sequence</code> constructed as specified
         * in RFC 3280
         */
        [Obsolete("Use 'GetInstance' instead")]
        public PolicyMappings(Asn1Sequence seq)
        {
            // TODO Validate length at least 1?
            // TODO[api] Asn1Sequence virtual (or extension?) method for mapping to a new sequence
            m_elements = DLSequence.Map(seq, Element.GetInstance);
        }

        public PolicyMappings(IDictionary<string, string> mappings)
        {
            Asn1EncodableVector v = new Asn1EncodableVector(mappings.Count);

            foreach (var entry in mappings)
            {
                var issuerDomainPolicy = new DerObjectIdentifier(entry.Key);
                var subjectDomainPolicy = new DerObjectIdentifier(entry.Value);

                v.Add(new Element(issuerDomainPolicy, subjectDomainPolicy));
            }

            m_elements = DLSequence.FromVector(v);
        }

        public PolicyMappings(IDictionary<DerObjectIdentifier, DerObjectIdentifier> mappings)
        {
            Asn1EncodableVector v = new Asn1EncodableVector(mappings.Count);

            foreach (var entry in mappings)
            {
                v.Add(new Element(issuerDomainPolicy: entry.Key, subjectDomainPolicy: entry.Value));
            }

            m_elements = DLSequence.FromVector(v);
        }

        public Asn1Sequence Elements => m_elements;

        public Element[] GetElements() => m_elements.MapElements(Element.GetInstance);

        public override Asn1Object ToAsn1Object() => m_elements;
    }
}
