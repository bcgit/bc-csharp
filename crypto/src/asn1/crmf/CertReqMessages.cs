namespace Org.BouncyCastle.Asn1.Crmf
{
    public class CertReqMessages
        : Asn1Encodable
    {
        public static CertReqMessages GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertReqMessages certReqMessages)
                return certReqMessages;
            return new CertReqMessages(Asn1Sequence.GetInstance(obj));
        }

        public static CertReqMessages GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqMessages(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertReqMessages GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqMessages(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private CertReqMessages(Asn1Sequence seq)
        {
            m_content = seq;
        }

        public CertReqMessages(params CertReqMsg[] msgs)
        {
            m_content = new DerSequence(msgs);
        }

        public virtual CertReqMsg[] ToCertReqMsgArray() => m_content.MapElements(CertReqMsg.GetInstance);

        /**
         * <pre>
         * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
