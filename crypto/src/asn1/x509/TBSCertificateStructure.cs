using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The TbsCertificate object.
     * <pre>
     * TbsCertificate ::= Sequence {
     *      version          [ 0 ]  Version DEFAULT v1(0),
     *      serialNumber            CertificateSerialNumber,
     *      signature               AlgorithmIdentifier,
     *      issuer                  Name,
     *      validity                Validity,
     *      subject                 Name,
     *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
     *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
     *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
     *      extensions        [ 3 ] Extensions OPTIONAL
     *      }
     * </pre>
     * <p>
     * Note: issuerUniqueID and subjectUniqueID are both deprecated by the IETF. This class
     * will parse them, but you really shouldn't be creating new ones.</p>
     */
    public class TbsCertificateStructure
		: Asn1Encodable
	{
        public static TbsCertificateStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TbsCertificateStructure tbsCertificateStructure)
                return tbsCertificateStructure;
            return new TbsCertificateStructure(Asn1Sequence.GetInstance(obj));
        }

        public static TbsCertificateStructure GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new TbsCertificateStructure(Asn1Sequence.GetInstance(obj, explicitly));

        public static TbsCertificateStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TbsCertificateStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_seq;

        private readonly DerInteger m_version;
        private readonly DerInteger m_serialNumber;
        private readonly AlgorithmIdentifier m_signature;
        private readonly X509Name m_issuer;
        private readonly Validity m_validity;
        private readonly X509Name m_subject;
        private readonly SubjectPublicKeyInfo m_subjectPublicKeyInfo;
        private readonly DerBitString m_issuerUniqueID;
        private readonly DerBitString m_subjectUniqueID;
        private readonly X509Extensions m_extensions;

        private TbsCertificateStructure(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 6 || count > 10)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerInteger.GetTagged)
                ?? DerInteger.Zero;

            bool isV1 = false, isV2 = false;
            if (m_version.HasValue(0))
            {
                isV1 = true;
            }
            else if (m_version.HasValue(1))
            {
                isV2 = true;
            }
            else if (!m_version.HasValue(2))
            {
                throw new ArgumentException("version number not recognised");
            }

            m_serialNumber = DerInteger.GetInstance(seq[pos++]);
            m_signature = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_issuer = X509Name.GetInstance(seq[pos++]);
            m_validity = Validity.GetInstance(seq[pos++]);
            m_subject = X509Name.GetInstance(seq[pos++]);
            m_subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(seq[pos++]);

            if (!isV1)
            {
                m_issuerUniqueID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerBitString.GetTagged);
                m_subjectUniqueID = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, DerBitString.GetTagged);

                if (!isV2)
                {
                    m_extensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, true, X509Extensions.GetTagged);
                }
            }

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

			m_seq = seq;
		}

		public int Version => m_version.IntValueExact + 1;

		public DerInteger VersionNumber => m_version;

		public DerInteger SerialNumber => m_serialNumber;

        public AlgorithmIdentifier Signature => m_signature;

        public X509Name Issuer => m_issuer;

        public Validity Validity => m_validity;

        public Time StartDate => Validity.NotBefore;

        public Time EndDate => Validity.NotAfter;

        public X509Name Subject => m_subject;

        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_subjectPublicKeyInfo;

        public DerBitString IssuerUniqueID => m_issuerUniqueID;

        public DerBitString SubjectUniqueID => m_subjectUniqueID;

        public X509Extensions Extensions => m_extensions;

		public override Asn1Object ToAsn1Object()
        {
            string property = Platform.GetEnvironmentVariable("Org.BouncyCastle.X509.Allow_Non-DER_TBSCert");
            if (null == property || Platform.EqualsIgnoreCase("true", property))
                return m_seq;

            Asn1EncodableVector v = new Asn1EncodableVector(10);

            // DEFAULT Zero
            if (!m_version.HasValue(0))
            {
                v.Add(new DerTaggedObject(true, 0, m_version));
            }

            v.Add(m_serialNumber, m_signature, m_issuer, m_validity, m_subject, m_subjectPublicKeyInfo);

            // Note: implicit tag
			v.AddOptionalTagged(false, 1, m_issuerUniqueID);

			// Note: implicit tag
			v.AddOptionalTagged(false, 2, m_subjectUniqueID);

			v.AddOptionalTagged(true, 3, m_extensions);

            return new DerSequence(v);
        }
    }
}
