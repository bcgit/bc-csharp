using System;

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

        public static OtherRecipientInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OtherRecipientInfo(Asn1Sequence.GetInstance(obj, explicitly));

        public static OtherRecipientInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRecipientInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_oriType;
        private readonly Asn1Encodable m_oriValue;

        public OtherRecipientInfo(DerObjectIdentifier oriType, Asn1Encodable oriValue)
        {
            m_oriType = oriType ?? throw new ArgumentNullException(nameof(oriType));
            m_oriValue = oriValue ?? throw new ArgumentNullException(nameof(oriValue));
        }

        private OtherRecipientInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_oriType = DerObjectIdentifier.GetInstance(seq[0]);
            m_oriValue = seq[1];
        }

        public virtual DerObjectIdentifier OriType => m_oriType;

        public virtual Asn1Encodable OriValue => m_oriValue;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OtherRecipientInfo ::= Sequence {
         *    oriType OBJECT IDENTIFIER,
         *    oriValue ANY DEFINED BY oriType }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_oriType, m_oriValue);
    }
}
