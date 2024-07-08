using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class OtherRevocationInfoFormat
        : Asn1Encodable
    {
        public static OtherRevocationInfoFormat GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherRevocationInfoFormat otherRevocationInfoFormat)
                return otherRevocationInfoFormat;
            return new OtherRevocationInfoFormat(Asn1Sequence.GetInstance(obj));
        }

        public static OtherRevocationInfoFormat GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new OtherRevocationInfoFormat(Asn1Sequence.GetInstance(obj, isExplicit));

        public static OtherRevocationInfoFormat GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRevocationInfoFormat(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_otherRevInfoFormat;
        private readonly Asn1Encodable m_otherRevInfo;

        public OtherRevocationInfoFormat(DerObjectIdentifier otherRevInfoFormat, Asn1Encodable otherRevInfo)
        {
            m_otherRevInfoFormat = otherRevInfoFormat ?? throw new ArgumentNullException(nameof(otherRevInfoFormat));
            m_otherRevInfo = otherRevInfo ?? throw new ArgumentNullException(nameof(otherRevInfo));
        }

        private OtherRevocationInfoFormat(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_otherRevInfoFormat = DerObjectIdentifier.GetInstance(seq[0]);
            m_otherRevInfo = seq[1];
        }

        public virtual DerObjectIdentifier InfoFormat => m_otherRevInfoFormat;

        public virtual Asn1Encodable Info => m_otherRevInfo;

        /** 
         * Produce an object suitable for an ASN1OutputStream.
         * <pre>
         * OtherRevocationInfoFormat ::= SEQUENCE {
         *      otherRevInfoFormat OBJECT IDENTIFIER,
         *      otherRevInfo ANY DEFINED BY otherRevInfoFormat }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_otherRevInfoFormat, m_otherRevInfo);
    }
}
