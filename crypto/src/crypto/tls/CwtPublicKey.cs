using System;
using System.Collections;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class CwtPublicKey : AbstractCertificate
    {
        private SubjectPublicKeyInfo mSubjectPublicKeyInfo;
        private byte[] mEncodedCwt;

        public CwtPublicKey(byte[] encodedCwt)
        {
            mEncodedCwt = encodedCwt;
        }

        public override void Encode(Stream output)
        {
            TlsUtilities.WriteOpaque24(mEncodedCwt, output);
        }

        public static CwtPublicKey Parse(Stream buf)
        {
            byte[] berEncoding = TlsUtilities.ReadOpaque24(buf);
           
            return new CwtPublicKey(berEncoding);
        }

        public override SubjectPublicKeyInfo SubjectPublicKeyInfo()
        {
            return mSubjectPublicKeyInfo;
        }

        public void SetSubjectPublicKeyInfo(SubjectPublicKeyInfo spki)
        {
            mSubjectPublicKeyInfo = spki;
        }

        public byte[] EncodedCwt()
        {
            return mEncodedCwt;
        }
    }
}
