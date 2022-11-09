using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class RevAnnContent
		: Asn1Encodable
	{
        public static RevAnnContent GetInstance(object obj)
        {
			if (obj is RevAnnContent revAnnContent)
				return revAnnContent;

			if (obj != null)
				return new RevAnnContent(Asn1Sequence.GetInstance(obj));

			return null;
        }

        private readonly PkiStatusEncodable m_status;
		private readonly CertId m_certID;
		private readonly Asn1GeneralizedTime m_willBeRevokedAt;
		private readonly Asn1GeneralizedTime m_badSinceDate;
		private readonly X509Extensions m_crlDetails;

        public RevAnnContent(PkiStatusEncodable status, CertId certID, Asn1GeneralizedTime willBeRevokedAt,
            Asn1GeneralizedTime badSinceDate)
            : this(status, certID, willBeRevokedAt, badSinceDate, null)
        {
		}

        public RevAnnContent(PkiStatusEncodable status, CertId certID, Asn1GeneralizedTime willBeRevokedAt,
            Asn1GeneralizedTime badSinceDate, X509Extensions crlDetails)
        {
            m_status = status;
            m_certID = certID;
            m_willBeRevokedAt = willBeRevokedAt;
            m_badSinceDate = badSinceDate;
            m_crlDetails = crlDetails;
        }

        private RevAnnContent(Asn1Sequence seq)
		{
			m_status = PkiStatusEncodable.GetInstance(seq[0]);
			m_certID = CertId.GetInstance(seq[1]);
			m_willBeRevokedAt = Asn1GeneralizedTime.GetInstance(seq[2]);
			m_badSinceDate = Asn1GeneralizedTime.GetInstance(seq[3]);

			if (seq.Count > 4)
			{
				m_crlDetails = X509Extensions.GetInstance(seq[4]);
			}
		}

		public virtual PkiStatusEncodable Status => m_status;

		public virtual CertId CertID => m_certID;

		public virtual Asn1GeneralizedTime WillBeRevokedAt => m_willBeRevokedAt;

		public virtual Asn1GeneralizedTime BadSinceDate => m_badSinceDate;

		public virtual X509Extensions CrlDetails => m_crlDetails;

		/**
		 * <pre>
		 * RevAnnContent ::= SEQUENCE {
		 *       status              PKIStatus,
		 *       certId              CertId,
		 *       willBeRevokedAt     GeneralizedTime,
		 *       badSinceDate        GeneralizedTime,
		 *       crlDetails          Extensions  OPTIONAL
		 *        -- extra CRL details (e.g., crl number, reason, location, etc.)
		 * }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(m_status, m_certID, m_willBeRevokedAt, m_badSinceDate);
			v.AddOptional(m_crlDetails);
			return new DerSequence(v);
		}
	}
}
