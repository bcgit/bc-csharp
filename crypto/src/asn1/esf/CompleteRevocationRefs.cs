using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
    /// </code>
    /// </remarks>
    public class CompleteRevocationRefs
		: Asn1Encodable
	{
		public static CompleteRevocationRefs GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is CompleteRevocationRefs completeRevocationRefs)
				return completeRevocationRefs;
			return new CompleteRevocationRefs(Asn1Sequence.GetInstance(obj));
		}

        public static CompleteRevocationRefs GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CompleteRevocationRefs(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_crlOcspRefs;

        private CompleteRevocationRefs(Asn1Sequence seq)
		{
			m_crlOcspRefs = seq;
            m_crlOcspRefs.MapElements(CrlOcspRef.GetInstance); // Validate
		}

		public CompleteRevocationRefs(params CrlOcspRef[] crlOcspRefs)
		{
			m_crlOcspRefs = DerSequence.FromElements(crlOcspRefs);
		}

		public CompleteRevocationRefs(IEnumerable<CrlOcspRef> crlOcspRefs)
		{
			if (crlOcspRefs == null)
                throw new ArgumentNullException(nameof(crlOcspRefs));

            m_crlOcspRefs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(crlOcspRefs));
		}

		public CrlOcspRef[] GetCrlOcspRefs() => m_crlOcspRefs.MapElements(CrlOcspRef.GetInstance);

		public override Asn1Object ToAsn1Object() => m_crlOcspRefs;
	}
}
