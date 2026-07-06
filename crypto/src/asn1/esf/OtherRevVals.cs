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
			int count = seq.Count, pos = 0;
			if (count != 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_otherRevValType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
			m_otherRevVals = Asn1Utilities.Read(seq, ref pos, element => element);

			if (pos != count)
				throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
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
