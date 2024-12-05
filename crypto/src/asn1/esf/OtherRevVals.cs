using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.3.2 Revocation Values Attribute Definition
    /// <code>
    /// OtherRevVals ::= SEQUENCE 
    /// {
    ///		otherRevValType      OtherRevValType,
    ///		otherRevVals         ANY DEFINED BY otherRevValType
    /// }
    ///
    /// OtherRevValType ::= OBJECT IDENTIFIER
    /// </code>
    /// </remarks>
    public class OtherRevVals
		: Asn1Encodable
	{
        public static OtherRevVals GetInstance(object obj)
        {
			if (obj == null)
				return null;
            if (obj is OtherRevVals otherRevVals)
                return otherRevVals;
            return new OtherRevVals(Asn1Sequence.GetInstance(obj));
        }

        public static OtherRevVals GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OtherRevVals(Asn1Sequence.GetInstance(obj, explicitly));

        public static OtherRevVals GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRevVals(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_otherRevValType;
        private readonly Asn1Encodable m_otherRevVals;

        private OtherRevVals(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count != 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_otherRevValType = DerObjectIdentifier.GetInstance(seq[0]);
			m_otherRevVals = seq[1];
		}

        public OtherRevVals(DerObjectIdentifier otherRevValType, Asn1Encodable otherRevVals)
        {
            m_otherRevValType = otherRevValType ?? throw new ArgumentNullException(nameof(otherRevValType));
            m_otherRevVals = otherRevVals ?? throw new ArgumentNullException(nameof(otherRevVals));
        }

		public DerObjectIdentifier OtherRevValType => m_otherRevValType;

		public Asn1Encodable OtherRevValsData => m_otherRevVals;

        [Obsolete("Use 'OtherRevValsData' instead")]
        public Asn1Object OtherRevValsObject => m_otherRevVals.ToAsn1Object();

		public override Asn1Object ToAsn1Object() => new DerSequence(m_otherRevValType, m_otherRevVals);
	}
}
