using System;

using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
	public class Evidence
		: Asn1Encodable, IAsn1Choice
	{
        public static Evidence GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Evidence evidence)
                return evidence;
            if (obj is Asn1TaggedObject taggedObject)
                return new Evidence(Asn1Utilities.CheckContextTagClass(taggedObject));

            throw new ArgumentException("Unknown object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static Evidence GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(obj, isExplicit, GetInstance);
        }

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

        private Evidence(Asn1TaggedObject tagged)
		{
            if (tagged.TagNo == 0)
            {
                m_tstEvidence = TimeStampTokenEvidence.GetInstance(tagged, false);
            }
            else if (tagged.TagNo == 1)
            {
                m_ersEvidence = EvidenceRecord.GetInstance(tagged, false);
            }
            else if (tagged.TagNo == 2)
            {
                m_otherEvidence = Asn1Sequence.GetInstance(tagged, false);
            }
            else
            {
                throw new ArgumentException("unknown tag in Evidence", nameof(tagged));
            }
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
