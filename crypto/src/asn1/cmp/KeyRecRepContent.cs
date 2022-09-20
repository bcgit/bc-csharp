using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class KeyRecRepContent
		: Asn1Encodable
	{
        public static KeyRecRepContent GetInstance(object obj)
        {
			if (obj is KeyRecRepContent keyRecRepContent)
				return keyRecRepContent;

			if (obj != null)
				return new KeyRecRepContent(Asn1Sequence.GetInstance(obj));

			return null;
        }

        private readonly PkiStatusInfo m_status;
		private readonly CmpCertificate m_newSigCert;
		private readonly Asn1Sequence m_caCerts;
		private readonly Asn1Sequence m_keyPairHist;

		private KeyRecRepContent(Asn1Sequence seq)
		{
			m_status = PkiStatusInfo.GetInstance(seq[0]);

			for (int pos = 1; pos < seq.Count; ++pos)
			{
				Asn1TaggedObject tObj = Asn1TaggedObject.GetInstance(seq[pos]);

				switch (tObj.TagNo)
				{
				case 0:
					m_newSigCert = CmpCertificate.GetInstance(tObj.GetObject());
					break;
				case 1:
					m_caCerts = Asn1Sequence.GetInstance(tObj.GetObject());
					break;
				case 2:
					m_keyPairHist = Asn1Sequence.GetInstance(tObj.GetObject());
					break;
				default:
					throw new ArgumentException("unknown tag number: " + tObj.TagNo, "seq");
				}
			}
		}

		public virtual PkiStatusInfo Status => m_status;

		public virtual CmpCertificate NewSigCert => m_newSigCert;

		public virtual CmpCertificate[] GetCACerts()
		{
			if (m_caCerts == null)
				return null;

			return m_caCerts.MapElements(CmpCertificate.GetInstance);
		}

		public virtual CertifiedKeyPair[] GetKeyPairHist()
		{
			if (m_keyPairHist == null)
				return null;

			return m_keyPairHist.MapElements(CertifiedKeyPair.GetInstance);
		}

		/**
		 * <pre>
		 * KeyRecRepContent ::= SEQUENCE {
		 *                         status                  PKIStatusInfo,
		 *                         newSigCert          [0] CMPCertificate OPTIONAL,
		 *                         caCerts             [1] SEQUENCE SIZE (1..MAX) OF
		 *                                                           CMPCertificate OPTIONAL,
		 *                         keyPairHist         [2] SEQUENCE SIZE (1..MAX) OF
		 *                                                           CertifiedKeyPair OPTIONAL
		 *              }
		 * </pre> 
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(m_status);
            v.AddOptionalTagged(true, 0, m_newSigCert);
            v.AddOptionalTagged(true, 1, m_caCerts);
            v.AddOptionalTagged(true, 2, m_keyPairHist);
			return new DerSequence(v);
		}
	}
}
