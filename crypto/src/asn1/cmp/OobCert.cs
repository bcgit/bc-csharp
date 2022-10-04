using System;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

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
                return GetInstance(cmpCertificate.GetEncoded());

            if (obj is byte[] bs)
            {
                try
                {
                    obj = Asn1Object.FromByteArray(bs);
                }
                catch (IOException)
                {
                    throw new ArgumentException("Invalid encoding in OobCert");
                }
            }

            if (obj is Asn1Sequence seq)
                return new OobCert(X509CertificateStructure.GetInstance(obj));

            if (obj is Asn1TaggedObject taggedObject)
                return new OobCert(taggedObject.TagNo, taggedObject.GetObject());

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static new OobCert GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            if (taggedObject == null)
                return null;

            if (!declaredExplicit)
                throw new ArgumentException("tag must be explicit");

            return GetInstance(taggedObject.GetObject());
        }

        public OobCert(int type, Asn1Encodable otherCert)
            : base(type, otherCert)
        {
        }

        public OobCert(X509CertificateStructure x509v3PKCert)
            : base(x509v3PKCert)
        {
        }
    }
}
