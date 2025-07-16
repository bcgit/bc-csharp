using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  CertAnnContent ::= CMPCertificate
     */
    // TODO[api] Remove and just use CmpCertificate
    public class CertAnnContent
        : CmpCertificate
    {
        public static new CertAnnContent GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static new CertAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static new CertAnnContent GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertAnnContent certAnnContent)
                return certAnnContent;

            X509CertificateStructure x509v3PKCert = X509CertificateStructure.GetOptional(element);
            if (x509v3PKCert != null)
                return new CertAnnContent(x509v3PKCert);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null && taggedObject.HasContextTag() && taggedObject.IsExplicit())
                return new CertAnnContent(taggedObject.TagNo, taggedObject.GetBaseObject());

            return null;
        }

        public static new CertAnnContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        [Obsolete("Use 'GetInstance' from tagged object instead")]
        public CertAnnContent(int type, Asn1Object otherCert)
            : base(type, otherCert)
        {
        }

        private CertAnnContent(int type, Asn1Encodable otherCert)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(type, otherCert)
#pragma warning restore CS0618 // Type or member is obsolete
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
