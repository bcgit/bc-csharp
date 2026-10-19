using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CertResponse structure of RFC 4210, the response to a single certificate request.</summary>
    public class CertResponse
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertResponse"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertResponse"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertResponse"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertResponse certResponse)
                return certResponse;
            return new CertResponse(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertResponse"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertResponse"/>.</returns>
        public static CertResponse GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertResponse(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertResponse"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertResponse"/>.</returns>
        public static CertResponse GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertResponse(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_certReqId;
        private readonly PkiStatusInfo m_status;
        private readonly CertifiedKeyPair m_certifiedKeyPair;
        private readonly Asn1OctetString m_rspInfo;

        private CertResponse(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certReqId = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_status = Asn1Utilities.Read(seq, ref pos, PkiStatusInfo.GetInstance);
            m_certifiedKeyPair = Asn1Utilities.ReadOptional(seq, ref pos, CertifiedKeyPair.GetOptional);
            m_rspInfo = Asn1Utilities.ReadOptional(seq, ref pos, Asn1OctetString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CertResponse"/>.</summary>
        /// <param name="certReqId">The cert req id.</param>
        /// <param name="status">The status.</param>
        public CertResponse(DerInteger certReqId, PkiStatusInfo status)
            : this(certReqId, status, null, null)
        {
        }

        /// <summary>Create a new <see cref="CertResponse"/>.</summary>
        /// <param name="certReqId">The cert req id.</param>
        /// <param name="status">The status.</param>
        /// <param name="certifiedKeyPair">The certified key pair.</param>
        /// <param name="rspInfo">The rsp info.</param>
        public CertResponse(DerInteger certReqId, PkiStatusInfo status, CertifiedKeyPair certifiedKeyPair,
            Asn1OctetString rspInfo)
        {
            m_certReqId = certReqId ?? throw new ArgumentNullException(nameof(certReqId));
            m_status = status ?? throw new ArgumentNullException(nameof(status));
            m_certifiedKeyPair = certifiedKeyPair;
            m_rspInfo = rspInfo;
        }

        /// <summary>Gets the cert req ID.</summary>
        public virtual DerInteger CertReqID => m_certReqId;

        /// <summary>Gets the status.</summary>
        public virtual PkiStatusInfo Status => m_status;

        /// <summary>Gets the certified key pair.</summary>
        public virtual CertifiedKeyPair CertifiedKeyPair => m_certifiedKeyPair;

        /// <summary>Gets the rsp info.</summary>
        public virtual Asn1OctetString RspInfo => m_rspInfo;

        /**
         * <pre>
         * CertResponse ::= SEQUENCE {
         *                            certReqId           INTEGER,
         *                            -- to match this response with corresponding request (a value
         *                            -- of -1 is to be used if certReqId is not specified in the
         *                            -- corresponding request)
         *                            status              PKIStatusInfo,
         *                            certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
         *                            rspInfo             OCTET STRING        OPTIONAL
         *                            -- analogous to the id-regInfo-utf8Pairs string defined
         *                            -- for regInfo in CertReqMsg [CRMF]
         *             }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_certReqId, m_status);
            v.AddOptional(m_certifiedKeyPair, m_rspInfo);
            return new DerSequence(v);
        }
    }
}
