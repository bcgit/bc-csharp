using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CertStatus
		: Asn1Encodable
	{
        public static CertStatus GetInstance(object obj)
        {
			if (obj is CertStatus certStatus)
				return certStatus;

			if (obj != null)
				return new CertStatus(Asn1Sequence.GetInstance(obj));

			return null;
        }

        private readonly Asn1OctetString m_certHash;
		private readonly DerInteger m_certReqID;
		private readonly PkiStatusInfo m_statusInfo;
        private readonly AlgorithmIdentifier m_hashAlg;

        private CertStatus(Asn1Sequence seq)
		{
			m_certHash = Asn1OctetString.GetInstance(seq[0]);
			m_certReqID = DerInteger.GetInstance(seq[1]);

			if (seq.Count > 2)
			{
				for (int t = 2; t < seq.Count; t++)
				{
					Asn1Object p = seq[t].ToAsn1Object();
					if (p is Asn1Sequence s)
					{
						m_statusInfo = PkiStatusInfo.GetInstance(s);
					}
					if (p is Asn1TaggedObject dto)
					{
						if (dto.TagNo != 0)
							throw new ArgumentException("unknown tag " + dto.TagNo);

						m_hashAlg = AlgorithmIdentifier.GetInstance(dto, true);
					}
				}
			}
		}

		public CertStatus(byte[] certHash, BigInteger certReqID)
		{
			m_certHash = new DerOctetString(certHash);
			m_certReqID = new DerInteger(certReqID);
		}

		public CertStatus(byte[] certHash, BigInteger certReqID, PkiStatusInfo statusInfo)
		{
            m_certHash = new DerOctetString(certHash);
            m_certReqID = new DerInteger(certReqID);
            m_statusInfo = statusInfo;
		}

        public CertStatus(byte[] certHash, BigInteger certReqID, PkiStatusInfo statusInfo, AlgorithmIdentifier hashAlg)
        {
            m_certHash = new DerOctetString(certHash);
            m_certReqID = new DerInteger(certReqID);
            m_statusInfo = statusInfo;
            m_hashAlg = hashAlg;
        }

        public virtual Asn1OctetString CertHash => m_certHash;

		public virtual DerInteger CertReqID => m_certReqID;

		public virtual PkiStatusInfo StatusInfo => m_statusInfo;

		public virtual AlgorithmIdentifier HashAlg => m_hashAlg;

        /**
         * <pre>
         *
         *  CertStatus ::= SEQUENCE {
         *     certHash    OCTET STRING,
         *     certReqId   INTEGER,
         *     statusInfo  PKIStatusInfo OPTIONAL,
         *     hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL
         *   }
         *
         * </pre>
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(m_certHash, m_certReqID);
			v.AddOptional(m_statusInfo);
			v.AddOptionalTagged(true, 0, m_hashAlg);
			return new DerSequence(v);
		}
	}
}
