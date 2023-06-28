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
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
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
					if (o is Asn1OctetString)
					{
						m_rspInfo = Asn1OctetString.GetInstance(o);
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
            if (certReqId == null)
				throw new ArgumentNullException(nameof(certReqId));

			if (status == null)
				throw new ArgumentNullException(nameof(status));

			m_certReqId = certReqId;
			m_status = status;
			m_certifiedKeyPair = certifiedKeyPair;
			m_rspInfo = rspInfo;
		}

		public virtual DerInteger CertReqID => m_certReqId;

		public virtual PkiStatusInfo Status => m_status;

		public virtual CertifiedKeyPair CertifiedKeyPair => m_certifiedKeyPair;

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
			Asn1EncodableVector v = new Asn1EncodableVector(m_certReqId, m_status);
			v.AddOptional(m_certifiedKeyPair, m_rspInfo);
			return new DerSequence(v);
		}
	}
}
