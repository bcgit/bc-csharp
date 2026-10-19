using System;

using Org.BouncyCastle.Asn1.Tsp;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
     * <a href="https://tools.ietf.org/html/rfc5544">RFC 5544</a>:
     * Binding Documents with Time-Stamps; Evidence object.
     * <p/>
     * <pre>
     * Evidence ::= CHOICE {
     *     tstEvidence    [0] TimeStampTokenEvidence,   -- see RFC 3161
     *     ersEvidence    [1] EvidenceRecord,           -- see RFC 4998
     *     otherEvidence  [2] OtherEvidence
     * }
     * </pre>
     */
    public class Evidence
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="Evidence"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Evidence"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Evidence"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Evidence GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="Evidence"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Evidence"/>.</returns>
        public static Evidence GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

        /// <summary>Return an <see cref="Evidence"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Evidence"/>, or null if <paramref name="element"/> is null.</returns>
        public static Evidence GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Evidence evidence)
                return evidence;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new Evidence(TimeStampTokenEvidence.GetTagged(taggedObject, false));

                if (taggedObject.HasContextTag(1))
                    return new Evidence(EvidenceRecord.GetTagged(taggedObject, false));

                if (taggedObject.HasContextTag(2))
                    return new Evidence(Asn1Sequence.GetTagged(taggedObject, false));
            }

            return null;
        }

        /// <summary>Return an <see cref="Evidence"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Evidence"/>.</returns>
        public static Evidence GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly TimeStampTokenEvidence m_tstEvidence;
        private readonly EvidenceRecord m_ersEvidence;
        private readonly Asn1Sequence m_otherEvidence;

        /// <summary>Create a new <see cref="Evidence"/>.</summary>
        /// <param name="tstEvidence">The tst evidence.</param>
        public Evidence(TimeStampTokenEvidence tstEvidence)
        {
            m_tstEvidence = tstEvidence ?? throw new ArgumentNullException(nameof(tstEvidence));
        }

        /// <summary>Create a new <see cref="Evidence"/>.</summary>
        /// <param name="ersEvidence">The ers evidence.</param>
        public Evidence(EvidenceRecord ersEvidence)
        {
            m_ersEvidence = ersEvidence ?? throw new ArgumentNullException(nameof(ersEvidence));
        }

        // TODO Add OtherEvidence class and public constructor for it here instead
        private Evidence(Asn1Sequence otherEvidence)
        {
            m_otherEvidence = otherEvidence ?? throw new ArgumentNullException(nameof(otherEvidence));
        }

        /// <summary>Gets the tst evidence.</summary>
        public virtual TimeStampTokenEvidence TstEvidence => m_tstEvidence;

        /// <summary>Gets the ers evidence.</summary>
        public virtual EvidenceRecord ErsEvidence => m_ersEvidence;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            if (m_tstEvidence != null)
                return new DerTaggedObject(false, 0, m_tstEvidence);
            if (m_ersEvidence != null)
                return new DerTaggedObject(false, 1, m_ersEvidence);
            return new DerTaggedObject(false, 2, m_otherEvidence);
        }
    }
}
