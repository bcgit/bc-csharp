using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * OOBCert ::= CMPCertificate
     */
    public class OobCert
        : CmpCertificate
    {
        public static new OobCert GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OobCert oobCert)
                return oobCert;
            if (obj is CmpCertificate cmpCertificate)
                return new OobCert(cmpCertificate);
            if (obj is Asn1TaggedObject taggedObject)
                return new OobCert(taggedObject);
            return new OobCert(X509CertificateStructure.GetInstance(obj));
        }

        public static new OobCert GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(taggedObject, declaredExplicit, GetInstance);
        }

        [Obsolete("Use constructor from Asn1TaggedObject instead")]
        public OobCert(int type, Asn1Encodable otherCert)
            : base(type, otherCert)
        {
        }

        internal OobCert(Asn1TaggedObject taggedObject)
            : base(taggedObject)
        {
        }

        internal OobCert(CmpCertificate other)
            : base(other)
        {
        }

        public OobCert(X509CertificateStructure x509v3PKCert)
            : base(x509v3PKCert)
        {
        }
    }
}
