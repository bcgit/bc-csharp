using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    public class CertificateConfirmationContentBuilder
    {
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        private DefaultDigestAlgorithmIdentifierFinder digestAlgFinder;
        private List<object> acceptedCerts = new List<object>();
        private List<object> acceptedReqIds = new List<object>();

        public CertificateConfirmationContentBuilder() : this(new DefaultDigestAlgorithmIdentifierFinder())
        {

        }
    
        public CertificateConfirmationContentBuilder(DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            this.digestAlgFinder = digestAlgFinder;
        }

        public CertificateConfirmationContentBuilder AddAcceptedCertificate(X509Certificate certHolder,
            BigInteger certReqId)
        {
            acceptedCerts.Add(certHolder);
            acceptedReqIds.Add(certReqId);
            return this;
        }

        public CertificateConfirmationContent Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            for (int i = 0; i != acceptedCerts.Count; i++)
            {
                X509Certificate cert = (X509Certificate) acceptedCerts[i];
                BigInteger reqId = (BigInteger) acceptedReqIds[i];


                
                AlgorithmIdentifier algorithmIdentifier =  sigAlgFinder.Find(cert.SigAlgName);

                AlgorithmIdentifier digAlg = digestAlgFinder.find(algorithmIdentifier);
                if (digAlg == null)
                {
                    throw new CmpException("cannot find algorithm for digest from signature");
                }

                DigestSink sink = new DigestSink(DigestUtilities.GetDigest(digAlg.Algorithm));

                sink.Write(cert.GetEncoded());

                byte[] dig = new byte[sink.Digest.GetDigestSize()];
                sink.Digest.DoFinal(dig, 0);

                v.Add(new CertStatus(dig,reqId));
            }

            return new CertificateConfirmationContent(CertConfirmContent.GetInstance(new DerSequence(v)),
                digestAlgFinder);
        }
    }
}
