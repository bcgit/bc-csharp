using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    public sealed class CertificateConfirmationContentBuilder
    {
        private readonly DefaultDigestAlgorithmIdentifierFinder m_digestAlgFinder;
        private readonly List<X509Certificate> m_acceptedCerts = new List<X509Certificate>();
        private readonly List<BigInteger> m_acceptedReqIDs = new List<BigInteger>();

        public CertificateConfirmationContentBuilder()
            : this(DefaultDigestAlgorithmIdentifierFinder.Instance)
        {
        }

        public CertificateConfirmationContentBuilder(DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            m_digestAlgFinder = digestAlgFinder;
        }

        public CertificateConfirmationContentBuilder AddAcceptedCertificate(X509Certificate certHolder,
            BigInteger certReqId)
        {
            m_acceptedCerts.Add(certHolder);
            m_acceptedReqIDs.Add(certReqId);
            return this;
        }

        public CertificateConfirmationContent Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(m_acceptedCerts.Count);
            for (int i = 0; i != m_acceptedCerts.Count; i++)
            {
                X509Certificate cert = m_acceptedCerts[i];
                BigInteger reqID = m_acceptedReqIDs[i];

                var sigAlgID = DefaultSignatureAlgorithmIdentifierFinder.Instance.Find(cert.SigAlgName)
                    ?? throw new CmpException("cannot find algorithm identifier for signature name");

                AlgorithmIdentifier digAlgID = m_digestAlgFinder.Find(sigAlgID)
                    ?? throw new CmpException("cannot find algorithm for digest from signature");

                byte[] digest = DigestUtilities.CalculateDigest(digAlgID.Algorithm, cert.GetEncoded());

                v.Add(new CertStatus(digest, reqID));
            }

            return new CertificateConfirmationContent(CertConfirmContent.GetInstance(new DerSequence(v)),
                m_digestAlgFinder);
        }
    }
}
