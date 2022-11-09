using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     * RevRepContent ::= SEQUENCE {
     *          status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
     *          -- in same order as was sent in RevReqContent
     *          revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
     *                                              OPTIONAL,
     *          -- IDs for which revocation was requested
     *          -- (same order as status)
     *          crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL
     *          -- the resulting CRLs (there may be more than one)
     *      }
     *</pre>
     */
    public class RevRepContent
		: Asn1Encodable
	{
        public static RevRepContent GetInstance(object obj)
        {
			if (obj is RevRepContent revRepContent)
				return revRepContent;

			if (obj != null)
				return new RevRepContent(Asn1Sequence.GetInstance(obj));

			return null;
        }

        private readonly Asn1Sequence m_status;
		private readonly Asn1Sequence m_revCerts;
		private readonly Asn1Sequence m_crls;

		private RevRepContent(Asn1Sequence seq)
		{
			m_status = Asn1Sequence.GetInstance(seq[0]);

			for (int pos = 1; pos < seq.Count; ++pos)
			{
				Asn1TaggedObject tObj = Asn1TaggedObject.GetInstance(seq[pos]);

				if (tObj.TagNo == 0)
				{
					m_revCerts = Asn1Sequence.GetInstance(tObj, true);
				}
				else
				{
					m_crls = Asn1Sequence.GetInstance(tObj, true);
				}
			}
		}

		public virtual PkiStatusInfo[] GetStatus()
		{
			return m_status.MapElements(PkiStatusInfo.GetInstance);
		}

		public virtual CertId[] GetRevCerts()
		{
			if (m_revCerts == null)
				return null;

			return m_revCerts.MapElements(CertId.GetInstance);
		}

		public virtual CertificateList[] GetCrls()
		{
			if (m_crls == null)
				return null;

			return m_crls.MapElements(CertificateList.GetInstance);
		}

		/**
		 * <pre>
		 * RevRepContent ::= SEQUENCE {
		 *        status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
		 *        -- in same order as was sent in RevReqContent
		 *        revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
		 *        -- IDs for which revocation was requested
		 *        -- (same order as status)
		 *        crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL
		 *        -- the resulting CRLs (there may be more than one)
		 *   }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(m_status);
            v.AddOptionalTagged(true, 0, m_revCerts);
            v.AddOptionalTagged(true, 1, m_crls);
			return new DerSequence(v);
		}
	}
}
