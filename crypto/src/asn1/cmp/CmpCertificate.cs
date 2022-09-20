using System;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class CmpCertificate
        : Asn1Encodable, IAsn1Choice
    {
        public static CmpCertificate GetInstance(object obj)
        {
            // TODO[cmp] Review this whole metho

            if (obj == null)
                return null;

            if (obj is CmpCertificate cmpCertificate)
                return cmpCertificate;

            if (obj is byte[] bs)
            {
                try
                {
                    obj = Asn1Object.FromByteArray(bs);
                }
                catch (IOException)
                {
                    throw new ArgumentException("Invalid encoding in CmpCertificate");
                }
            }

            if (obj is Asn1Sequence)
                return new CmpCertificate(X509CertificateStructure.GetInstance(obj));

            if (obj is Asn1TaggedObject taggedObject)
                return new CmpCertificate(taggedObject.TagNo, taggedObject.GetObject());

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static CmpCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            // TODO[cmp]
            if (taggedObject == null)
                return null;

            if (!declaredExplicit)
                throw new ArgumentException("tag must be explicit");

            // TODO[cmp]
            return GetInstance(taggedObject.GetObject());
        }

        private readonly X509CertificateStructure m_x509v3PKCert;

        private readonly int m_otherTagValue;
        private readonly Asn1Encodable m_otherCert;

        /**
         * Note: the addition of other certificates is a BC extension. If you use this constructor they
         * will be added with an explicit tag value of type.
         *
         * @param type      the type of the certificate (used as a tag value).
         * @param otherCert the object representing the certificate
         */
        public CmpCertificate(int type, Asn1Encodable otherCert)
        {
            m_otherTagValue = type;
            m_otherCert = otherCert;
        }

        public CmpCertificate(X509CertificateStructure x509v3PKCert)
        {
            if (x509v3PKCert.Version != 3)
                throw new ArgumentException("only version 3 certificates allowed", nameof(x509v3PKCert));

            m_x509v3PKCert = x509v3PKCert;
        }

        public virtual bool IsX509v3PKCert => m_x509v3PKCert != null;

        public virtual X509CertificateStructure X509v3PKCert => m_x509v3PKCert;

        public virtual int OtherCertTag => m_otherTagValue;

        public virtual Asn1Encodable OtherCert => m_otherCert;

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
            if (m_otherCert != null)
            {
                // explicit following CMP conventions
                return new DerTaggedObject(true, m_otherTagValue, m_otherCert);
            }

            return m_x509v3PKCert.ToAsn1Object();
        }
    }
}
