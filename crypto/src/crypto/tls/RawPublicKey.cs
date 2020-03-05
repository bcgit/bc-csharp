using System;
using System.Collections;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class RawPublicKey : AbstractCertificate
    {
        private SubjectPublicKeyInfo mSubjectPublicKeyInfo;

        public RawPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            mSubjectPublicKeyInfo = subjectPublicKeyInfo;
        }

        public override void Encode(Stream output)
        {
            byte[] derEncoding = mSubjectPublicKeyInfo.GetEncoded(Asn1Encodable.Der);
            TlsUtilities.WriteOpaque24(derEncoding, output);
        }

        public static RawPublicKey Parse(Stream buf)
        {
            byte[] berEncoding = TlsUtilities.ReadOpaque24(buf);
            Asn1Object asn1Cert = TlsUtilities.ReadAsn1Object(berEncoding);
           
            return new RawPublicKey(Asn1.X509.SubjectPublicKeyInfo.GetInstance(asn1Cert));
        }

        public override SubjectPublicKeyInfo SubjectPublicKeyInfo()
        {
            return mSubjectPublicKeyInfo;
        }
    }
}
