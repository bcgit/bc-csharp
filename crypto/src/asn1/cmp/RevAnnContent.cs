using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class RevAnnContent
		: Asn1Encodable
	{
        public static RevAnnContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RevAnnContent revAnnContent)
                return revAnnContent;
            return new RevAnnContent(Asn1Sequence.GetInstance(obj));
        }

        public static RevAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevAnnContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static RevAnnContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevAnnContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

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
            m_status = status ?? throw new ArgumentNullException(nameof(status));
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_willBeRevokedAt = willBeRevokedAt ?? throw new ArgumentNullException(nameof(willBeRevokedAt));
            m_badSinceDate = badSinceDate ?? throw new ArgumentNullException(nameof(badSinceDate));
            m_crlDetails = crlDetails;
        }

        private RevAnnContent(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_status = PkiStatusEncodable.GetInstance(seq[pos++]);
            m_certID = CertId.GetInstance(seq[pos++]);
            m_willBeRevokedAt = Asn1GeneralizedTime.GetInstance(seq[pos++]);
            m_badSinceDate = Asn1GeneralizedTime.GetInstance(seq[pos++]);
            m_crlDetails = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
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
			Asn1EncodableVector v = new Asn1EncodableVector(5);
			v.Add(m_status, m_certID, m_willBeRevokedAt, m_badSinceDate);
			v.AddOptional(m_crlDetails);
			return new DerSequence(v);
		}
	}
}
