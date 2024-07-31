using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class CmpCertificate
        : Asn1Encodable, IAsn1Choice
    {
        public static CmpCertificate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CmpCertificate cmpCertificate)
                return cmpCertificate;
            if (obj is X509CertificateStructure certificate)
                return new CmpCertificate(certificate);
            if (obj is Asn1TaggedObject taggedObject)
                return new CmpCertificate(taggedObject);

            Asn1Object asn1Object = null;
            if (obj is IAsn1Convertible asn1Convertible)
            {
                asn1Object = asn1Convertible.ToAsn1Object();
            }
            else if (obj is byte[] bytes)
            {
                asn1Object = Asn1Object.FromByteArray(bytes);
            }

            if (asn1Object is Asn1TaggedObject asn1TaggedObject)
                return new CmpCertificate(asn1TaggedObject);

            return new CmpCertificate(X509CertificateStructure.GetInstance(asn1Object ?? obj));
        }

        public static CmpCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static CmpCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly X509CertificateStructure m_x509v3PKCert;

        private readonly int m_otherTag;
        private readonly Asn1Encodable m_otherObject;

        [Obsolete("Use 'GetInstance' from tagged object instead")]
        public CmpCertificate(int type, Asn1Encodable otherCert)
        {
            m_otherTag = type;
            m_otherObject = otherCert;
        }

        internal CmpCertificate(Asn1TaggedObject taggedObject)
        {
            Asn1Encodable otherCert;
            if (taggedObject.HasContextTag(1))
            {
                otherCert = AttributeCertificate.GetInstance(taggedObject, true);
            }
            else
            {
                throw new ArgumentException("Invalid CHOICE element", nameof(taggedObject));
            }

            m_otherTag = taggedObject.TagNo;
            m_otherObject = taggedObject.GetExplicitBaseObject();
        }

        internal CmpCertificate(CmpCertificate other)
        {
            m_x509v3PKCert = other.m_x509v3PKCert;
            m_otherTag = other.m_otherTag;
            m_otherObject = other.m_otherObject;
        }

        public CmpCertificate(X509CertificateStructure x509v3PKCert)
        {
            if (x509v3PKCert.Version != 3)
                throw new ArgumentException("only version 3 certificates allowed", nameof(x509v3PKCert));

            m_x509v3PKCert = x509v3PKCert;
        }

        public virtual bool IsX509v3PKCert => m_x509v3PKCert != null;

        public virtual X509CertificateStructure X509v3PKCert => m_x509v3PKCert;

        public virtual int OtherCertTag => m_otherTag;

        public virtual Asn1Encodable OtherCert => m_otherObject;

        /**
         * <pre>
         * CMPCertificate ::= CHOICE {
         *            x509v3PKCert        Certificate
         *            x509v2AttrCert      [1] AttributeCertificate
         *  }
         * </pre>
         * Note: the addition of attribute certificates is a BC extension.
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_otherObject != null)
                return new DerTaggedObject(true, m_otherTag, m_otherObject);
            if (m_x509v3PKCert != null)
                return m_x509v3PKCert.ToAsn1Object();
            throw new InvalidOperationException();
        }
    }
}
