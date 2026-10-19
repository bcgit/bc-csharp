using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The AttributeCertificateInfo structure of RFC 5755.</summary>
    public class AttributeCertificateInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AttributeCertificateInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AttributeCertificateInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AttributeCertificateInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AttributeCertificateInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributeCertificateInfo attributeCertificateInfo)
                return attributeCertificateInfo;
            return new AttributeCertificateInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AttributeCertificateInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributeCertificateInfo"/>.</returns>
        public static AttributeCertificateInfo GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new AttributeCertificateInfo(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="AttributeCertificateInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributeCertificateInfo"/>.</returns>
        public static AttributeCertificateInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeCertificateInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Holder m_holder;
        private readonly AttCertIssuer m_issuer;
        private readonly AlgorithmIdentifier m_signature;
        private readonly DerInteger m_serialNumber;
        private readonly AttCertValidityPeriod m_attrCertValidityPeriod;
        private readonly Asn1Sequence m_attributes;
        private readonly DerBitString m_issuerUniqueID;
        private readonly X509Extensions m_extensions;

        private AttributeCertificateInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 6 || count > 9)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional) ?? DerInteger.Zero;
            m_holder = Asn1Utilities.Read(seq, ref pos, Holder.GetInstance);
            m_issuer = Asn1Utilities.Read(seq, ref pos, AttCertIssuer.GetInstance);
            m_signature = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_serialNumber = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_attrCertValidityPeriod = Asn1Utilities.Read(seq, ref pos, AttCertValidityPeriod.GetInstance);
            m_attributes = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);
            m_issuerUniqueID = Asn1Utilities.ReadOptional(seq, ref pos, DerBitString.GetOptional);
            m_extensions = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            // RFC 3281 sec. 4.2.3: the attribute certificate issuer MUST identify the issuer; an empty AttCertIssuer is
            // not a valid identifier.
            if (IsEmptyIssuer(m_issuer))
                throw new ArgumentException("attribute certificate issuer is empty");
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        public Holder Holder => m_holder;

        public AttCertIssuer Issuer => m_issuer;

        /// <summary>Gets the signature.</summary>
        public AlgorithmIdentifier Signature => m_signature;

        /// <summary>Gets the serial number.</summary>
        public DerInteger SerialNumber => m_serialNumber;

        /// <summary>Gets the attr cert validity period.</summary>
        public AttCertValidityPeriod AttrCertValidityPeriod => m_attrCertValidityPeriod;

        /// <summary>Gets the attributes.</summary>
        public Asn1Sequence Attributes => m_attributes;

        /// <summary>Gets the issuer unique ID.</summary>
        public DerBitString IssuerUniqueID => m_issuerUniqueID;

        public X509Extensions Extensions => m_extensions;

        /// <summary>
        /// Return true when the AttCertIssuer carries no identifying information: an empty v1 GeneralNames sequence, or
        /// a v2 V2Form whose issuerName, baseCertificateID and objectDigestInfo are all absent (or whose issuerName,
        /// when present, is itself empty).
        /// </summary>
        internal static bool IsEmptyIssuer(AttCertIssuer issuer)
        {
            Asn1Encodable inner = issuer.Issuer;

            if (inner is GeneralNames generalNames)
                return generalNames.GetNames().Length == 0;

            if (inner is V2Form v2)
            {
                GeneralNames issuerName = v2.IssuerName;
                if (issuerName != null)
                    return issuerName.GetNames().Length == 0;

                return v2.BaseCertificateID == null && v2.ObjectDigestInfo == null;
            }

            return false;
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  AttributeCertificateInfo ::= Sequence {
         *       version              AttCertVersion -- version is v2,
         *       holder               Holder,
         *       issuer               AttCertIssuer,
         *       signature            AlgorithmIdentifier,
         *       serialNumber         CertificateSerialNumber,
         *       attrCertValidityPeriod   AttCertValidityPeriod,
         *       attributes           Sequence OF Attr,
         *       issuerUniqueID       UniqueIdentifier OPTIONAL,
         *       extensions           Extensions OPTIONAL
         *  }
         *
         *  AttCertVersion ::= Integer { v2(1) }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(9);
            if (!m_version.HasValue(0))
            {
                v.Add(m_version);
            }
            v.Add(m_holder, m_issuer, m_signature, m_serialNumber, m_attrCertValidityPeriod, m_attributes);
            v.AddOptional(m_issuerUniqueID, m_extensions);
            return new DerSequence(v);
        }
    }
}
