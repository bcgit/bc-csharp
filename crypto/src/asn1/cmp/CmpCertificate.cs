using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class CmpCertificate
        : Asn1Encodable, IAsn1Choice
    {
        public static CmpCertificate GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static CmpCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static CmpCertificate GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CmpCertificate cmpCertificate)
                return cmpCertificate;

            X509CertificateStructure x509v3PKCert = X509CertificateStructure.GetOptional(element);
            if (x509v3PKCert != null)
                return new CmpCertificate(x509v3PKCert);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null && taggedObject.HasContextTag() && taggedObject.IsExplicit())
            {
#pragma warning disable CS0618 // Type or member is obsolete
                return new CmpCertificate(taggedObject.TagNo, taggedObject.GetBaseObject());
#pragma warning restore CS0618 // Type or member is obsolete
            }

            return null;
        }

        public static CmpCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly X509CertificateStructure m_x509v3PKCert;

        private readonly int m_otherCertTag;
        private readonly Asn1Encodable m_otherCert;

        [Obsolete("Use 'GetInstance' from tagged object instead")]
        public CmpCertificate(int type, Asn1Encodable otherCert)
        {
            m_x509v3PKCert = null;
            m_otherCertTag = type;
            m_otherCert = otherCert;
        }

        internal CmpCertificate(CmpCertificate other)
        {
            m_x509v3PKCert = other.m_x509v3PKCert;
            m_otherCertTag = other.m_otherCertTag;
            m_otherCert = other.m_otherCert;
        }

        public CmpCertificate(X509CertificateStructure x509v3PKCert)
        {
            if (x509v3PKCert.Version != 3)
                throw new ArgumentException("only version 3 certificates allowed", nameof(x509v3PKCert));

            m_x509v3PKCert = x509v3PKCert;
            m_otherCertTag = -1;
            m_otherCert = null;
        }

        public virtual bool IsX509v3PKCert => m_x509v3PKCert != null;

        public virtual X509CertificateStructure X509v3PKCert => m_x509v3PKCert;

        public virtual int OtherCertTag => m_otherCertTag;

        public virtual Asn1Encodable OtherCert => m_otherCert;

        /**
         * <pre>
         * CMPCertificate ::= CHOICE {
         *            x509v3PKCert    Certificate
         *            otherCert      [tag] EXPLICIT ANY DEFINED BY tag
         *  }
         * </pre>
         * Note: the addition of the explicit tagging is a BC extension. We apologise for the warped syntax, but hopefully you get the idea.
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_x509v3PKCert != null)
                return m_x509v3PKCert.ToAsn1Object();
            if (m_otherCert != null)
                return new DerTaggedObject(true, m_otherCertTag, m_otherCert);
            throw new InvalidOperationException();
        }
    }
}
