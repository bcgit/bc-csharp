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
        public static Evidence GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static Evidence GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

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

        public static Evidence GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly TimeStampTokenEvidence m_tstEvidence;
        private readonly EvidenceRecord m_ersEvidence;
        private readonly Asn1Sequence m_otherEvidence;

        public Evidence(TimeStampTokenEvidence tstEvidence)
		{
			m_tstEvidence = tstEvidence ?? throw new ArgumentNullException(nameof(tstEvidence));
		}

        public Evidence(EvidenceRecord ersEvidence)
        {
            m_ersEvidence = ersEvidence ?? throw new ArgumentNullException(nameof(ersEvidence));
        }

        // TODO Add OtherEvidence class and public constructor for it here instead
        private Evidence(Asn1Sequence otherEvidence)
        {
            m_otherEvidence = otherEvidence ?? throw new ArgumentNullException(nameof(otherEvidence));
        }

        public virtual TimeStampTokenEvidence TstEvidence => m_tstEvidence;

        public virtual EvidenceRecord ErsEvidence => m_ersEvidence;

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
