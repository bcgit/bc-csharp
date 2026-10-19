namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The CertReqMessages structure of RFC 4211: a sequence of certificate request messages.</summary>
    public class CertReqMessages
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertReqMessages"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertReqMessages"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertReqMessages"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertReqMessages GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertReqMessages certReqMessages)
                return certReqMessages;
            return new CertReqMessages(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertReqMessages"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertReqMessages"/>.</returns>
        public static CertReqMessages GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqMessages(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertReqMessages"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertReqMessages"/>.</returns>
        public static CertReqMessages GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqMessages(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private CertReqMessages(Asn1Sequence seq)
        {
            m_content = seq;
        }

        /// <summary>Create a new <see cref="CertReqMessages"/>.</summary>
        /// <param name="msg">The message.</param>
        public CertReqMessages(CertReqMsg msg)
        {
            m_content = DerSequence.FromElement(msg);
        }

        /// <summary>Create a new <see cref="CertReqMessages"/>.</summary>
        /// <param name="msgs">The msgs.</param>
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
