using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  CertAnnContent ::= CMPCertificate
     */
    public class CertAnnContent
        : CmpCertificate
    {
        public static new CertAnnContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertAnnContent certAnnContent)
                return certAnnContent;
            if (obj is CmpCertificate cmpCertificate)
                return new CertAnnContent(cmpCertificate);
            if (obj is Asn1TaggedObject taggedObject)
                return new CertAnnContent(taggedObject);
            return new CertAnnContent(X509CertificateStructure.GetInstance(obj));
        }

        public static new CertAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(taggedObject, declaredExplicit, GetInstance);
        }

        [Obsolete("Use 'GetInstance' from tagged object instead")]
        public CertAnnContent(int type, Asn1Object otherCert)
            : base(type, otherCert)
        {
        }

        internal CertAnnContent(Asn1TaggedObject taggedObject)
            : base(taggedObject)
        {
        }

        internal CertAnnContent(CmpCertificate other)
            : base(other)
        {
        }

        public CertAnnContent(X509CertificateStructure x509v3PKCert)
            : base(x509v3PKCert)
        {
        }
    }
}
