using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class CertReqMsg
        : Asn1Encodable
    {
        public static CertReqMsg GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertReqMsg certReqMsg)
                return certReqMsg;
            return new CertReqMsg(Asn1Sequence.GetInstance(obj));
        }

        public static CertReqMsg GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new CertReqMsg(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private readonly CertRequest m_certReq;
        private readonly ProofOfPossession m_pop;
        private readonly Asn1Sequence m_regInfo;

        private CertReqMsg(Asn1Sequence seq)
        {
            m_certReq = CertRequest.GetInstance(seq[0]);

            for (int pos = 1; pos < seq.Count; ++pos)
            {
                object o = seq[pos];

                if (o is Asn1TaggedObject || o is ProofOfPossession)
                {
                    m_pop = ProofOfPossession.GetInstance(o);
                }
                else
                {
                    m_regInfo = Asn1Sequence.GetInstance(o);
                }
            }
        }

        /**
         * Creates a new CertReqMsg.
         * @param certReq CertRequest
         * @param popo may be null
         * @param regInfo may be null
         */
        public CertReqMsg(CertRequest certReq, ProofOfPossession popo, AttributeTypeAndValue[] regInfo)
        {
            this.m_certReq = certReq ?? throw new ArgumentNullException(nameof(certReq));
            this.m_pop = popo;

            if (regInfo != null)
            {
                this.m_regInfo = new DerSequence(regInfo);
            }
        }

        public virtual CertRequest CertReq => m_certReq;

        public virtual ProofOfPossession Pop => m_pop;

        [Obsolete("Use 'Pop' instead")]
        public virtual ProofOfPossession Popo => m_pop;

        public virtual AttributeTypeAndValue[] GetRegInfo() =>
            m_regInfo?.MapElements(AttributeTypeAndValue.GetInstance);

        /**
         * <pre>
         * CertReqMsg ::= SEQUENCE {
         *                    certReq   CertRequest,
         *                    pop       ProofOfPossession  OPTIONAL,
         *                    -- content depends upon key type
         *                    regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_certReq);
            v.AddOptional(m_pop, m_regInfo);
            return new DerSequence(v);
        }
    }
}
