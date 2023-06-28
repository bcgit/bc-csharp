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
        private static readonly DefaultSignatureAlgorithmIdentifierFinder SigAlgFinder =
            new DefaultSignatureAlgorithmIdentifierFinder();

        private readonly DefaultDigestAlgorithmIdentifierFinder m_digestAlgFinder;
        private readonly IList<X509Certificate> m_acceptedCerts = new List<X509Certificate>();
        private readonly IList<BigInteger> m_acceptedReqIDs = new List<BigInteger>();

        public CertificateConfirmationContentBuilder()
            : this(new DefaultDigestAlgorithmIdentifierFinder())
        {
        }

        public CertificateConfirmationContentBuilder(DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            this.m_digestAlgFinder = digestAlgFinder;
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

                AlgorithmIdentifier algorithmIdentifier = SigAlgFinder.Find(cert.SigAlgName);
                if (null == algorithmIdentifier)
                    throw new CmpException("cannot find algorithm identifier for signature name");

                AlgorithmIdentifier digAlg = m_digestAlgFinder.Find(algorithmIdentifier);
                if (null == digAlg)
                    throw new CmpException("cannot find algorithm for digest from signature");

                byte[] digest = DigestUtilities.CalculateDigest(digAlg.Algorithm, cert.GetEncoded());

                v.Add(new CertStatus(digest, reqID));
            }

            return new CertificateConfirmationContent(CertConfirmContent.GetInstance(new DerSequence(v)),
                m_digestAlgFinder);
        }
    }
}
