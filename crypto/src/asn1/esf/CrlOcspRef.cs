using System;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
	/// <code>
	/// CrlOcspRef ::= SEQUENCE {
	///		crlids		[0] CRLListID		OPTIONAL,
	/// 	ocspids		[1] OcspListID		OPTIONAL,
	/// 	otherRev	[2] OtherRevRefs	OPTIONAL
	/// }
	/// </code>
	/// </remarks>
	public class CrlOcspRef
		: Asn1Encodable
	{
        public static CrlOcspRef GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlOcspRef crlOcspRef)
                return crlOcspRef;
            return new CrlOcspRef(Asn1Sequence.GetInstance(obj));
        }

        public static CrlOcspRef GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CrlOcspRef(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly CrlListID m_crlids;
        private readonly OcspListID m_ocspids;
        private readonly OtherRevRefs m_otherRev;

        private CrlOcspRef(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

			m_crlids = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, CrlListID.GetTagged);
            m_ocspids = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, OcspListID.GetTagged);
            m_otherRev = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, OtherRevRefs.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public CrlOcspRef(CrlListID crlids, OcspListID ocspids, OtherRevRefs otherRev)
        {
            m_crlids = crlids;
			m_ocspids = ocspids;
			m_otherRev = otherRev;
		}

		public CrlListID CrlIDs => m_crlids;

		public OcspListID OcspIDs => m_ocspids;

		public OtherRevRefs OtherRev => m_otherRev;

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.AddOptionalTagged(true, 0, m_crlids);
            v.AddOptionalTagged(true, 1, m_ocspids);
            v.AddOptionalTagged(true, 2, m_otherRev);
			return DerSequence.FromVector(v);
		}
	}
}
