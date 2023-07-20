using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CertResponse
		: Asn1Encodable
	{
        public static CertResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertResponse certResponse)
                return certResponse;
            return new CertResponse(Asn1Sequence.GetInstance(obj));
        }

        public static CertResponse GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CertResponse(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_certReqId;
		private readonly PkiStatusInfo m_status;
		private readonly CertifiedKeyPair m_certifiedKeyPair;
		private readonly Asn1OctetString m_rspInfo;

		private CertResponse(Asn1Sequence seq)
		{
			m_certReqId = DerInteger.GetInstance(seq[0]);
			m_status = PkiStatusInfo.GetInstance(seq[1]);

			if (seq.Count >= 3)
			{
				if (seq.Count == 3)
				{
					Asn1Encodable o = seq[2];
					if (o is Asn1OctetString octetString)
					{
						m_rspInfo = octetString;
					}
					else
					{
						m_certifiedKeyPair = CertifiedKeyPair.GetInstance(o);
					}
				}
				else
				{
					m_certifiedKeyPair = CertifiedKeyPair.GetInstance(seq[2]);
					m_rspInfo = Asn1OctetString.GetInstance(seq[3]);
				}
			}
		}

		public CertResponse(DerInteger certReqId, PkiStatusInfo status)
			: this(certReqId, status, null, null)
		{
		}

        public CertResponse(DerInteger certReqId, PkiStatusInfo status, CertifiedKeyPair certifiedKeyPair,
            Asn1OctetString rspInfo)
        {
			m_certReqId = certReqId ?? throw new ArgumentNullException(nameof(certReqId));
			m_status = status ?? throw new ArgumentNullException(nameof(status));
            m_certifiedKeyPair = certifiedKeyPair;
			m_rspInfo = rspInfo;
		}

		public virtual DerInteger CertReqID => m_certReqId;

		public virtual PkiStatusInfo Status => m_status;

		public virtual CertifiedKeyPair CertifiedKeyPair => m_certifiedKeyPair;

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
