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
        /// <summary>A mapping between an issuer domain policy and a subject domain policy.</summary>
        public class Element
            : Asn1Encodable
        {
            /// <summary>Return an <see cref="Element"/> from the given object.</summary>
            /// <param name="obj">
            /// An <see cref="Element"/>, an object from which one can be constructed, or null.
            /// </param>
            /// <returns>The <see cref="Element"/>, or null if <paramref name="obj"/> is null.</returns>
            public static Element GetInstance(object obj)
            {
                if (obj == null)
                    return null;
                if (obj is Element element)
                    return element;
                return new Element(Asn1Sequence.GetInstance(obj));
            }

            /// <summary>Return an <see cref="Element"/> from a tagged object.</summary>
            /// <param name="taggedObject">The tagged object.</param>
            /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
            /// <returns>The <see cref="Element"/>.</returns>
            public static Element GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
                new Element(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

            /// <summary>Return an <see cref="Element"/> from a tagged object.</summary>
            /// <param name="taggedObject">The tagged object.</param>
            /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
            /// <returns>The <see cref="Element"/>.</returns>
            public static Element GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
                new Element(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

            private readonly DerObjectIdentifier m_issuerDomainPolicy;
            private readonly DerObjectIdentifier m_subjectDomainPolicy;

            private Element(Asn1Sequence seq)
            {
                int count = seq.Count, pos = 0;
                if (count != 2)
                    throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

                m_issuerDomainPolicy = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
                m_subjectDomainPolicy = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);

                if (pos != count)
                    throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
            }

            /// <summary>Create a new <see cref="Element"/>.</summary>
            /// <param name="issuerDomainPolicy">The issuer domain policy.</param>
            /// <param name="subjectDomainPolicy">The subject domain policy.</param>
            public Element(DerObjectIdentifier issuerDomainPolicy, DerObjectIdentifier subjectDomainPolicy)
            {
                m_issuerDomainPolicy = issuerDomainPolicy ?? throw new ArgumentNullException(nameof(issuerDomainPolicy));
                m_subjectDomainPolicy = subjectDomainPolicy ?? throw new ArgumentNullException(nameof(subjectDomainPolicy));
            }

            /// <summary>Gets the issuer domain policy.</summary>
            public DerObjectIdentifier IssuerDomainPolicy => m_issuerDomainPolicy;

            /// <summary>Gets the subject domain policy.</summary>
            public DerObjectIdentifier SubjectDomainPolicy => m_subjectDomainPolicy;

            /// <inheritdoc/>
            public override Asn1Object ToAsn1Object() => new DLSequence(m_issuerDomainPolicy, m_subjectDomainPolicy);
        }

        /// <summary>Return an <see cref="PolicyMappings"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PolicyMappings"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PolicyMappings"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="PolicyMappings"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PolicyMappings"/>.</returns>
        public static PolicyMappings GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new PolicyMappings(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        // TODO[asn1] Tighten to DLSequence if/when safe
        private readonly DerSequence m_elements;

        /**
         * Creates a new <code>PolicyMappings</code> instance.
         *
         * @param seq an <code>Asn1Sequence</code> constructed as specified
         * in RFC 3280
         */
        [Obsolete("Use 'GetInstance' instead")]
        public PolicyMappings(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));
            if (seq.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(seq));

            // TODO[api] Asn1Sequence virtual (or extension?) method for mapping to a new sequence
            m_elements = DerSequence.Map(seq, Element.GetInstance);
        }

        /// <summary>Create a new <see cref="PolicyMappings"/>.</summary>
        /// <param name="mappings">The mappings.</param>
        public PolicyMappings(IDictionary<string, string> mappings)
        {
            if (mappings == null)
                throw new ArgumentNullException(nameof(mappings));
            if (mappings.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(mappings));

            Asn1EncodableVector v = new Asn1EncodableVector(mappings.Count);

            foreach (var entry in mappings)
            {
                var issuerDomainPolicy = new DerObjectIdentifier(entry.Key);
                var subjectDomainPolicy = new DerObjectIdentifier(entry.Value);

                v.Add(new Element(issuerDomainPolicy, subjectDomainPolicy));
            }

            m_elements = DerSequence.FromVector(v);
        }

        /// <summary>Create a new <see cref="PolicyMappings"/>.</summary>
        /// <param name="mappings">The mappings.</param>
        public PolicyMappings(IDictionary<DerObjectIdentifier, DerObjectIdentifier> mappings)
        {
            if (mappings == null)
                throw new ArgumentNullException(nameof(mappings));
            if (mappings.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(mappings));

            Asn1EncodableVector v = new Asn1EncodableVector(mappings.Count);

            foreach (var entry in mappings)
            {
                v.Add(new Element(issuerDomainPolicy: entry.Key, subjectDomainPolicy: entry.Value));
            }

            m_elements = DerSequence.FromVector(v);
        }

        /// <summary>Gets the elements.</summary>
        public Asn1Sequence Elements => m_elements;

        /// <summary>Return the elements.</summary>
        public Element[] GetElements() => m_elements.MapElements(Element.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_elements;
    }
}
