using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * an X509Certificate structure.
     * <pre>
     *  Certificate ::= Sequence {
     *      tbsCertificate          TbsCertificate,
     *      signatureAlgorithm      AlgorithmIdentifier,
     *      signature               BIT STRING
     *  }
     * </pre>
     */
    public class X509CertificateStructure
        : Asn1Encodable
    {
        public static X509CertificateStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is X509CertificateStructure x509CertificateStructure)
                return x509CertificateStructure;
            return new X509CertificateStructure(Asn1Sequence.GetInstance(obj));
        }

        public static X509CertificateStructure GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new X509CertificateStructure(Asn1Sequence.GetInstance(obj, explicitly));

        public static X509CertificateStructure GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is X509CertificateStructure x509CertificateStructure)
                return x509CertificateStructure;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new X509CertificateStructure(asn1Sequence);

            return null;
        }

        public static X509CertificateStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new X509CertificateStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly TbsCertificateStructure m_tbsCert;
        private readonly AlgorithmIdentifier m_sigAlgID;
        private readonly DerBitString m_sig;

        // TODO[api] Fix parameter names
        public X509CertificateStructure(TbsCertificateStructure tbsCert, AlgorithmIdentifier sigAlgID, DerBitString sig)
        {
            m_tbsCert = tbsCert ?? throw new ArgumentNullException(nameof(tbsCert));
            m_sigAlgID = sigAlgID ?? throw new ArgumentNullException(nameof(sigAlgID));
            m_sig = sig ?? throw new ArgumentNullException(nameof(sig));
        }

        private X509CertificateStructure(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            //
            // correct x509 certficate
            //
            m_tbsCert = TbsCertificateStructure.GetInstance(seq[0]);
            m_sigAlgID = AlgorithmIdentifier.GetInstance(seq[1]);
            m_sig = DerBitString.GetInstance(seq[2]);
        }

        public TbsCertificateStructure TbsCertificate => m_tbsCert;

        public int Version => m_tbsCert.Version;

        public DerInteger SerialNumber => m_tbsCert.SerialNumber;

        public X509Name Issuer => m_tbsCert.Issuer;

        public Validity Validity => m_tbsCert.Validity;

        public Time StartDate => m_tbsCert.StartDate;

        public Time EndDate => m_tbsCert.EndDate;

        public X509Name Subject => m_tbsCert.Subject;

        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_tbsCert.SubjectPublicKeyInfo;

        public DerBitString IssuerUniqueID => m_tbsCert.IssuerUniqueID;

        public DerBitString SubjectUniqueID => m_tbsCert.SubjectUniqueID;

        public X509Extensions Extensions => m_tbsCert.Extensions;

        public AlgorithmIdentifier SignatureAlgorithm => m_sigAlgID;

        public DerBitString Signature => m_sig;

        public byte[] GetSignatureOctets() => m_sig.GetOctets();

        public override Asn1Object ToAsn1Object() => new DerSequence(m_tbsCert, m_sigAlgID, m_sig);
    }
}
