using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * PKIX RFC-2459
     *
     * The X.509 v2 CRL syntax is as follows.  For signature calculation,
     * the data that is to be signed is ASN.1 Der encoded.
     *
     * <pre>
     * CertificateList  ::=  Sequence  {
     *      tbsCertList          TbsCertList,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     * </pre>
     */
    public class CertificateList
        : Asn1Encodable
    {
        public static CertificateList GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificateList certificateList)
                return certificateList;
            return new CertificateList(Asn1Sequence.GetInstance(obj));
        }

        public static CertificateList GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new CertificateList(Asn1Sequence.GetInstance(obj, explicitly));

        public static CertificateList GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertificateList certificateList)
                return certificateList;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new CertificateList(asn1Sequence);

            return null;
        }

        public static CertificateList GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificateList(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly TbsCertificateList m_tbsCertList;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signatureValue;

        private CertificateList(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_tbsCertList = TbsCertificateList.GetInstance(seq[0]);
			m_signatureAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);
			m_signatureValue = DerBitString.GetInstance(seq[2]);
        }

        public TbsCertificateList TbsCertList => m_tbsCertList;

		public CrlEntry[] GetRevokedCertificates() => m_tbsCertList.GetRevokedCertificates();

		public IEnumerable<CrlEntry> GetRevokedCertificateEnumeration() =>
            m_tbsCertList.GetRevokedCertificateEnumeration();

		public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        public DerBitString Signature => m_signatureValue;

        public byte[] GetSignatureOctets() => m_signatureValue.GetOctets();

        public int Version => m_tbsCertList.Version;

		public X509Name Issuer => m_tbsCertList.Issuer;

		public Time ThisUpdate => m_tbsCertList.ThisUpdate;

		public Time NextUpdate => m_tbsCertList.NextUpdate;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_tbsCertList, m_signatureAlgorithm, m_signatureValue);
    }
}
