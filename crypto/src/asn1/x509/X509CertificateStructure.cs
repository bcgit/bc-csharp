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
        /// <summary>Return an <see cref="X509CertificateStructure"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="X509CertificateStructure"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="X509CertificateStructure"/>, or null if <paramref name="obj"/> is null.</returns>
        public static X509CertificateStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is X509CertificateStructure x509CertificateStructure)
                return x509CertificateStructure;
            return new X509CertificateStructure(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="X509CertificateStructure"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="X509CertificateStructure"/>.</returns>
        public static X509CertificateStructure GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new X509CertificateStructure(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="X509CertificateStructure"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>
        /// The <see cref="X509CertificateStructure"/>, or null if <paramref name="element"/> is null.
        /// </returns>
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

        /// <summary>Return an <see cref="X509CertificateStructure"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="X509CertificateStructure"/>.</returns>
        public static X509CertificateStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new X509CertificateStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly TbsCertificateStructure m_tbsCert;
        private readonly AlgorithmIdentifier m_sigAlgID;
        private readonly DerBitString m_sig;

        /// <summary>Create a new <see cref="X509CertificateStructure"/>.</summary>
        /// <param name="tbsCert">The tbs cert.</param>
        /// <param name="sigAlgID">The sig alg ID.</param>
        /// <param name="sig">The signature.</param>
        // TODO[api] Fix parameter names
        public X509CertificateStructure(TbsCertificateStructure tbsCert, AlgorithmIdentifier sigAlgID, DerBitString sig)
        {
            m_tbsCert = tbsCert ?? throw new ArgumentNullException(nameof(tbsCert));
            m_sigAlgID = sigAlgID ?? throw new ArgumentNullException(nameof(sigAlgID));
            m_sig = sig ?? throw new ArgumentNullException(nameof(sig));
        }

        private X509CertificateStructure(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            //
            // correct x509 certficate
            //
            m_tbsCert = Asn1Utilities.Read(seq, ref pos, TbsCertificateStructure.GetInstance);
            m_sigAlgID = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_sig = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the tbs certificate.</summary>
        public TbsCertificateStructure TbsCertificate => m_tbsCert;

        /// <summary>Gets the version.</summary>
        public int Version => m_tbsCert.Version;

        /// <summary>Gets the serial number.</summary>
        public DerInteger SerialNumber => m_tbsCert.SerialNumber;

        /// <summary>Gets the issuer.</summary>
        public X509Name Issuer => m_tbsCert.Issuer;

        public Validity Validity => m_tbsCert.Validity;

        /// <summary>Gets the start date.</summary>
        public Time StartDate => m_tbsCert.StartDate;

        /// <summary>Gets the end date.</summary>
        public Time EndDate => m_tbsCert.EndDate;

        /// <summary>Gets the subject.</summary>
        public X509Name Subject => m_tbsCert.Subject;

        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_tbsCert.SubjectPublicKeyInfo;

        /// <summary>Gets the issuer unique ID.</summary>
        public DerBitString IssuerUniqueID => m_tbsCert.IssuerUniqueID;

        /// <summary>Gets the subject unique ID.</summary>
        public DerBitString SubjectUniqueID => m_tbsCert.SubjectUniqueID;

        /// <summary>Gets the extensions.</summary>
        public X509Extensions Extensions => m_tbsCert.Extensions;

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => m_sigAlgID;

        /// <summary>Gets the signature.</summary>
        public DerBitString Signature => m_sig;

        /// <summary>Return the signature octets.</summary>
        public byte[] GetSignatureOctets() => m_sig.GetOctets();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_tbsCert, m_sigAlgID, m_sig);
    }
}
