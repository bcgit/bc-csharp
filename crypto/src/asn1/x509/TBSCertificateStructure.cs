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
        /// <summary>Return an <see cref="TbsCertificateStructure"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TbsCertificateStructure"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TbsCertificateStructure"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TbsCertificateStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TbsCertificateStructure tbsCertificateStructure)
                return tbsCertificateStructure;
            return new TbsCertificateStructure(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="TbsCertificateStructure"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TbsCertificateStructure"/>.</returns>
        public static TbsCertificateStructure GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new TbsCertificateStructure(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="TbsCertificateStructure"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TbsCertificateStructure"/>.</returns>
        public static TbsCertificateStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TbsCertificateStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

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

        private readonly Asn1Sequence m_seq;

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

            m_serialNumber = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_signature = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_issuer = Asn1Utilities.Read(seq, ref pos, X509Name.GetInstance);
            m_validity = Asn1Utilities.Read(seq, ref pos, Validity.GetInstance);
            m_subject = Asn1Utilities.Read(seq, ref pos, X509Name.GetInstance);
            m_subjectPublicKeyInfo = Asn1Utilities.Read(seq, ref pos, SubjectPublicKeyInfo.GetInstance);

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

            // RFC 5280 sec. 4.1.2.4: certificate issuer MUST be a non-empty DN.
            if (m_issuer.IsEmpty && !Properties.GetBoolean(Properties.X509AllowEmptyIssuerCert, false))
                throw new ArgumentException("certificate issuer is an empty distinguished name");

            m_seq = seq;
        }

        /// <summary>Create a new <see cref="TbsCertificateStructure"/>.</summary>
        /// <param name="version">The version.</param>
        /// <param name="serialNumber">The serial number.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="issuer">The issuer.</param>
        /// <param name="validity">The validity.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="subjectPublicKeyInfo">The subject public key info.</param>
        /// <param name="issuerUniqueID">The issuer unique ID.</param>
        /// <param name="subjectUniqueID">The subject unique ID.</param>
        /// <param name="extensions">The extensions.</param>
        public TbsCertificateStructure(DerInteger version, DerInteger serialNumber, AlgorithmIdentifier signature,
            X509Name issuer, Validity validity, X509Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo,
            DerBitString issuerUniqueID, DerBitString subjectUniqueID, X509Extensions extensions)
        {
            m_version = version ?? DerInteger.Zero;
            m_serialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
            m_signature = signature ?? throw new ArgumentNullException(nameof(signature));
            m_issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            m_validity = validity ?? throw new ArgumentNullException(nameof(validity));
            m_subject = subject ?? throw new ArgumentNullException(nameof(subject));
            m_subjectPublicKeyInfo = subjectPublicKeyInfo ??
                throw new ArgumentNullException(nameof(subjectPublicKeyInfo));
            m_issuerUniqueID = issuerUniqueID;
            m_subjectUniqueID = subjectUniqueID;
            m_extensions = extensions;

            // RFC 5280 sec. 4.1.2.4: certificate issuer MUST be a non-empty DN.
            if (m_issuer.IsEmpty)
                throw new ArgumentException("certificate issuer is an empty distinguished name");

            m_seq = null;
        }

        /// <summary>Gets the version.</summary>
        public int Version => m_version.IntValueExact + 1;

        /// <summary>Gets the version number.</summary>
        public DerInteger VersionNumber => m_version;

        /// <summary>Gets the serial number.</summary>
        public DerInteger SerialNumber => m_serialNumber;

        /// <summary>Gets the signature.</summary>
        public AlgorithmIdentifier Signature => m_signature;

        /// <summary>Gets the issuer.</summary>
        public X509Name Issuer => m_issuer;

        /// <summary>Gets the validity.</summary>
        public Validity Validity => m_validity;

        /// <summary>Gets the start date.</summary>
        public Time StartDate => Validity.NotBefore;

        /// <summary>Gets the end date.</summary>
        public Time EndDate => Validity.NotAfter;

        /// <summary>Gets the subject.</summary>
        public X509Name Subject => m_subject;

        /// <summary>Gets the subject public key info.</summary>
        public SubjectPublicKeyInfo SubjectPublicKeyInfo => m_subjectPublicKeyInfo;

        /// <summary>Gets the issuer unique ID.</summary>
        public DerBitString IssuerUniqueID => m_issuerUniqueID;

        /// <summary>Gets the subject unique ID.</summary>
        public DerBitString SubjectUniqueID => m_subjectUniqueID;

        /// <summary>Gets the extensions.</summary>
        public X509Extensions Extensions => m_extensions;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            if (m_seq != null)
            {
                if (Properties.GetBoolean(Properties.X509AllowNonDerTbsCertificate, true))
                    return m_seq;
            }

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
