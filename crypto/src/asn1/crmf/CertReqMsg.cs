using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>
    /// The CertReqMsg structure of RFC 4211: a certificate request with optional proof of possession and registration
    /// info.
    /// </summary>
    public class CertReqMsg
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertReqMsg"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CertReqMsg"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CertReqMsg"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertReqMsg GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertReqMsg certReqMsg)
                return certReqMsg;
            return new CertReqMsg(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertReqMsg"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertReqMsg"/>.</returns>
        public static CertReqMsg GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new CertReqMsg(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="CertReqMsg"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertReqMsg"/>.</returns>
        public static CertReqMsg GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertReqMsg(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CertRequest m_certReq;
        private readonly ProofOfPossession m_pop;
        private readonly Asn1Sequence m_regInfo;

        private CertReqMsg(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_certReq = Asn1Utilities.Read(seq, ref pos, CertRequest.GetInstance);
            m_pop = Asn1Utilities.ReadOptional(seq, ref pos, ProofOfPossession.GetOptional);
            m_regInfo = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
         * Creates a new CertReqMsg.
         * @param certReq CertRequest
         * @param popo may be null
         * @param regInfo may be null
         */
        public CertReqMsg(CertRequest certReq, ProofOfPossession popo, AttributeTypeAndValue[] regInfo)
        {
            m_certReq = certReq ?? throw new ArgumentNullException(nameof(certReq));
            m_pop = popo;
            m_regInfo = regInfo == null ? null : new DerSequence(regInfo);
        }

        public virtual CertRequest CertReq => m_certReq;

        /// <summary>Gets the pop.</summary>
        public virtual ProofOfPossession Pop => m_pop;

        /// <summary>Gets the popo.</summary>
        [Obsolete("Use 'Pop' instead")]
        public virtual ProofOfPossession Popo => m_pop;

        /// <summary>Return the reg info.</summary>
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
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_certReq);
            v.AddOptional(m_pop, m_regInfo);
            return new DerSequence(v);
        }
    }
}
