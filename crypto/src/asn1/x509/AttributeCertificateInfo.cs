using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class AttributeCertificateInfo
        : Asn1Encodable
    {
        public static AttributeCertificateInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributeCertificateInfo attributeCertificateInfo)
                return attributeCertificateInfo;
            return new AttributeCertificateInfo(Asn1Sequence.GetInstance(obj));
        }

        public static AttributeCertificateInfo GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new AttributeCertificateInfo(Asn1Sequence.GetInstance(obj, isExplicit));

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
            m_holder = Holder.GetInstance(seq[pos++]);
            m_issuer = AttCertIssuer.GetInstance(seq[pos++]);
            m_signature = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_serialNumber = DerInteger.GetInstance(seq[pos++]);
            m_attrCertValidityPeriod = AttCertValidityPeriod.GetInstance(seq[pos++]);
            m_attributes = Asn1Sequence.GetInstance(seq[pos++]);
            m_issuerUniqueID = Asn1Utilities.ReadOptional(seq, ref pos, DerBitString.GetOptional);
            m_extensions = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DerInteger Version => m_version;

        public Holder Holder => m_holder;

        public AttCertIssuer Issuer => m_issuer;

        public AlgorithmIdentifier Signature => m_signature;

        public DerInteger SerialNumber => m_serialNumber;

        public AttCertValidityPeriod AttrCertValidityPeriod => m_attrCertValidityPeriod;

        public Asn1Sequence Attributes => m_attributes;

        public DerBitString IssuerUniqueID => m_issuerUniqueID;

        public X509Extensions Extensions => m_extensions;

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
