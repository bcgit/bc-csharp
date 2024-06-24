using System;

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
            if (obj == null)
                return null;
            if (obj is RevRepContent revRepContent)
                return revRepContent;
            return new RevRepContent(Asn1Sequence.GetInstance(obj));
        }

        public static RevRepContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new RevRepContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_status;
		private readonly Asn1Sequence m_revCerts;
		private readonly Asn1Sequence m_crls;

		private RevRepContent(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_status = Asn1Sequence.GetInstance(seq[pos++]);
			m_revCerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetTagged);
            m_crls = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public virtual PkiStatusInfo[] GetStatus() => m_status.MapElements(PkiStatusInfo.GetInstance);

		public virtual CertId[] GetRevCerts() => m_revCerts?.MapElements(CertId.GetInstance);

		public virtual CertificateList[] GetCrls() => m_crls?.MapElements(CertificateList.GetInstance);

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
			Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.Add(m_status);
            v.AddOptionalTagged(true, 0, m_revCerts);
            v.AddOptionalTagged(true, 1, m_crls);
			return new DerSequence(v);
		}
	}
}
