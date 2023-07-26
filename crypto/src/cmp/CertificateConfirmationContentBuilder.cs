using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    public sealed class CertificateConfirmationContentBuilder
    {
        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;
        private readonly List<X509Certificate> m_acceptedCerts = new List<X509Certificate>();
        private readonly List<BigInteger> m_acceptedReqIDs = new List<BigInteger>();

        public CertificateConfirmationContentBuilder()
            : this(DefaultDigestAlgorithmFinder.Instance)
        {
        }

        [Obsolete("Use constructor taking 'IDigestAlgorithmFinder' instead")]
        public CertificateConfirmationContentBuilder(Org.BouncyCastle.Cms.DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
            : this((IDigestAlgorithmFinder)digestAlgFinder)
        {
        }

        public CertificateConfirmationContentBuilder(IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            m_digestAlgorithmFinder = digestAlgorithmFinder;
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

                var sigAlgID = DefaultSignatureAlgorithmFinder.Instance.Find(cert.SigAlgName)
                    ?? throw new CmpException("cannot find algorithm identifier for signature name");

                var digAlgID = m_digestAlgorithmFinder.Find(sigAlgID)
                    ?? throw new CmpException("cannot find algorithm for digest from signature");

                byte[] digest = DigestUtilities.CalculateDigest(digAlgID.Algorithm, cert.GetEncoded());

                v.Add(new CertStatus(digest, reqID));
            }

            var content = CertConfirmContent.GetInstance(new DerSequence(v));

            return new CertificateConfirmationContent(content, m_digestAlgorithmFinder);
        }
    }
}
