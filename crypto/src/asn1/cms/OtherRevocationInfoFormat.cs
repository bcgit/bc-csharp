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

        public static OtherRevocationInfoFormat GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new OtherRevocationInfoFormat(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private readonly DerObjectIdentifier otherRevInfoFormat;
        private readonly Asn1Encodable otherRevInfo;

        public OtherRevocationInfoFormat(
            DerObjectIdentifier otherRevInfoFormat,
            Asn1Encodable otherRevInfo)
        {
            this.otherRevInfoFormat = otherRevInfoFormat;
            this.otherRevInfo = otherRevInfo;
        }

        private OtherRevocationInfoFormat(Asn1Sequence seq)
        {
            otherRevInfoFormat = DerObjectIdentifier.GetInstance(seq[0]);
            otherRevInfo = seq[1];
        }

        public virtual DerObjectIdentifier InfoFormat
        {
            get { return otherRevInfoFormat; }
        }

        public virtual Asn1Encodable Info
        {
            get { return otherRevInfo; }
        }

        /** 
         * Produce an object suitable for an ASN1OutputStream.
         * <pre>
         * OtherRevocationInfoFormat ::= SEQUENCE {
         *      otherRevInfoFormat OBJECT IDENTIFIER,
         *      otherRevInfo ANY DEFINED BY otherRevInfoFormat }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(otherRevInfoFormat, otherRevInfo);
        }
    }
}
