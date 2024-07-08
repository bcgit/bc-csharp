using System;

using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CertifiedKeyPair
		: Asn1Encodable
	{
        public static CertifiedKeyPair GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertifiedKeyPair certifiedKeyPair)
                return certifiedKeyPair;
            return new CertifiedKeyPair(Asn1Sequence.GetInstance(obj));
        }

        public static CertifiedKeyPair GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertifiedKeyPair(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertifiedKeyPair GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertifiedKeyPair certifiedKeyPair)
                return certifiedKeyPair;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new CertifiedKeyPair(asn1Sequence);

            return null;
        }

        public static CertifiedKeyPair GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertifiedKeyPair(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CertOrEncCert m_certOrEncCert;
		private readonly EncryptedKey m_privateKey;
		private readonly PkiPublicationInfo m_publicationInfo;

        private CertifiedKeyPair(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certOrEncCert = CertOrEncCert.GetInstance(seq[pos++]);
            m_privateKey = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, EncryptedKey.GetTagged);
            m_publicationInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, PkiPublicationInfo.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		public CertifiedKeyPair(CertOrEncCert certOrEncCert)
			: this(certOrEncCert, (EncryptedKey)null, null)
		{
		}

        [Obsolete("Use constructor with EncryptedKey instead")]
        public CertifiedKeyPair(CertOrEncCert certOrEncCert, EncryptedValue privateKey,
            PkiPublicationInfo publicationInfo)
            : this(certOrEncCert, privateKey == null ? null : new EncryptedKey(privateKey), publicationInfo)
        {
        }

        public CertifiedKeyPair(CertOrEncCert certOrEncCert, EncryptedKey privateKey,
			PkiPublicationInfo publicationInfo)
        {
            m_certOrEncCert = certOrEncCert ?? throw new ArgumentNullException(nameof(certOrEncCert));
            m_privateKey = privateKey;
            m_publicationInfo = publicationInfo;
        }

		public virtual CertOrEncCert CertOrEncCert => m_certOrEncCert;

		public virtual EncryptedKey PrivateKey => m_privateKey;

		public virtual PkiPublicationInfo PublicationInfo => m_publicationInfo;

		/**
		 * RFC 9480
		 * <pre>
		 * CertifiedKeyPair ::= SEQUENCE {
         *     certOrEncCert       CertOrEncCert,
         *     privateKey      [0] EncryptedKey        OPTIONAL,
         *     -- See [RFC4211] for comments on encoding.
         *     publicationInfo [1] PKIPublicationInfo  OPTIONAL
         * }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.Add(m_certOrEncCert);
            v.AddOptionalTagged(true, 0, m_privateKey);
            v.AddOptionalTagged(true, 1, m_publicationInfo);
			return new DerSequence(v);
		}
	}
}
