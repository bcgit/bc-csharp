using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CRLListID ::= SEQUENCE 
    /// {
    ///		crls	SEQUENCE OF CrlValidatedID
    /// }
    /// </code>
    /// </remarks>
    public class CrlListID
		: Asn1Encodable
	{
        public static CrlListID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlListID crlListID)
                return crlListID;
            return new CrlListID(Asn1Sequence.GetInstance(obj));
        }

        public static CrlListID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CrlListID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_crls;

        private CrlListID(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count != 1)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_crls = Asn1Sequence.GetInstance(seq[0]);
			m_crls.MapElements(CrlValidatedID.GetInstance); // Validate
		}

		public CrlListID(params CrlValidatedID[] crls)
		{
			if (crls == null)
				throw new ArgumentNullException(nameof(crls));

			m_crls = DerSequence.FromElements(crls);
		}

		public CrlListID(IEnumerable<CrlValidatedID> crls)
		{
			if (crls == null)
                throw new ArgumentNullException(nameof(crls));

            m_crls = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(crls));
		}

		public CrlValidatedID[] GetCrls() => m_crls.MapElements(CrlValidatedID.GetInstance);

		public override Asn1Object ToAsn1Object() => new DerSequence(m_crls);
	}
}
