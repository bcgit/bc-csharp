namespace Org.BouncyCastle.Asn1.Cms
{
    public class OtherRecipientInfo
        : Asn1Encodable
    {
        public static OtherRecipientInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherRecipientInfo otherRecipientInfo)
                return otherRecipientInfo;
            return new OtherRecipientInfo(Asn1Sequence.GetInstance(obj));
        }

        public static OtherRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new OtherRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly DerObjectIdentifier oriType;
        private readonly Asn1Encodable oriValue;

        public OtherRecipientInfo(
            DerObjectIdentifier	oriType,
            Asn1Encodable		oriValue)
        {
            this.oriType = oriType;
            this.oriValue = oriValue;
        }

        private OtherRecipientInfo(Asn1Sequence seq)
        {
            oriType = DerObjectIdentifier.GetInstance(seq[0]);
            oriValue = seq[1];
        }

        public virtual DerObjectIdentifier OriType
        {
            get { return oriType; }
        }

        public virtual Asn1Encodable OriValue
        {
            get { return oriValue; }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OtherRecipientInfo ::= Sequence {
         *    oriType OBJECT IDENTIFIER,
         *    oriValue ANY DEFINED BY oriType }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(oriType, oriValue);
        }
    }
}
