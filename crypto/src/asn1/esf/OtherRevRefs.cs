using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OtherRevRefs ::= SEQUENCE 
    /// {
    ///		otherRevRefType      OtherRevRefType,
    ///		otherRevRefs         ANY DEFINED BY otherRevRefType
    /// }
    ///
    /// OtherRevRefType ::= OBJECT IDENTIFIER
    /// </code>
    /// </remarks>
    public class OtherRevRefs
		: Asn1Encodable
	{
		public static OtherRevRefs GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is OtherRevRefs otherRevRefs)
				return otherRevRefs;
			return new OtherRevRefs(Asn1Sequence.GetInstance(obj));
		}

        public static OtherRevRefs GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRevRefs(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OtherRevRefs GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRevRefs(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_otherRevRefType;
        private readonly Asn1Encodable m_otherRevRefs;

        private OtherRevRefs(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_otherRevRefType = DerObjectIdentifier.GetInstance(seq[0]);
			m_otherRevRefs = seq[1];
		}

        public OtherRevRefs(DerObjectIdentifier otherRevRefType, Asn1Encodable otherRevRefs)
        {
			m_otherRevRefType = otherRevRefType ?? throw new ArgumentNullException(nameof(otherRevRefType));
            m_otherRevRefs = otherRevRefs ?? throw new ArgumentNullException(nameof(otherRevRefs));
        }

        public DerObjectIdentifier OtherRevRefType => m_otherRevRefType;

		public Asn1Encodable OtherRevRefsData => m_otherRevRefs;

		[Obsolete("Use 'OtherRevRefsData' instead")]
		public Asn1Object OtherRevRefsObject => m_otherRevRefs.ToAsn1Object();

		public override Asn1Object ToAsn1Object() => new DerSequence(m_otherRevRefType, m_otherRevRefs);
	}
}
