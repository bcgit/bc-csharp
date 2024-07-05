using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class AttributeCertificate
        : Asn1Encodable
    {
        public static AttributeCertificate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributeCertificate attributeCertificate)
                return attributeCertificate;
            return new AttributeCertificate(Asn1Sequence.GetInstance(obj));
        }

        public static AttributeCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static AttributeCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AttributeCertificateInfo m_acinfo;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signatureValue;

		private AttributeCertificate(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_acinfo = AttributeCertificateInfo.GetInstance(seq[0]);
            m_signatureAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);
            m_signatureValue = DerBitString.GetInstance(seq[2]);
        }

        public AttributeCertificate(AttributeCertificateInfo acinfo, AlgorithmIdentifier signatureAlgorithm,
            DerBitString signatureValue)
        {
            m_acinfo = acinfo ?? throw new ArgumentNullException(nameof(acinfo));
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_signatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
        }

        public AttributeCertificateInfo ACInfo => m_acinfo;

        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        public DerBitString SignatureValue => m_signatureValue;

        public byte[] GetSignatureOctets() => m_signatureValue.GetOctets();

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  AttributeCertificate ::= Sequence {
         *       acinfo               AttributeCertificateInfo,
         *       signatureAlgorithm   AlgorithmIdentifier,
         *       signatureValue       BIT STRING
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_acinfo, m_signatureAlgorithm, m_signatureValue);
    }
}
