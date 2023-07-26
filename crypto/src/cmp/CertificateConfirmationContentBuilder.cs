using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    public sealed class CertificateConfirmationContentBuilder
    {
        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;
        private readonly List<CmpCertificate> m_acceptedCerts = new List<CmpCertificate>();
        private readonly List<AlgorithmIdentifier> m_acceptedSignatureAlgorithms = new List<AlgorithmIdentifier>();
        private readonly List<DerInteger> m_acceptedReqIDs = new List<DerInteger>();

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

        // TODO[api] Rename parameters to 'cert', 'certReqID'
        public CertificateConfirmationContentBuilder AddAcceptedCertificate(X509Certificate certHolder,
            BigInteger certReqId)
        {
            return AddAcceptedCertificate(certHolder, new DerInteger(certReqId));
        }

        public CertificateConfirmationContentBuilder AddAcceptedCertificate(X509Certificate cert, DerInteger certReqID)
        {
            return AddAcceptedCertificate(
                new CmpCertificate(cert.CertificateStructure), cert.SignatureAlgorithm, certReqID);
        }

        public CertificateConfirmationContentBuilder AddAcceptedCertificate(CmpCertificate cmpCertificate,
            AlgorithmIdentifier signatureAlgorithm, DerInteger certReqID)
        {
            m_acceptedCerts.Add(cmpCertificate);
            m_acceptedSignatureAlgorithms.Add(signatureAlgorithm);
            m_acceptedReqIDs.Add(certReqID);

            return this;
        }

        public CertificateConfirmationContent Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(m_acceptedCerts.Count);
            for (int i = 0; i != m_acceptedCerts.Count; i++)
            {
                CmpCertificate cmpCertificate = m_acceptedCerts[i];
                AlgorithmIdentifier signatureAlgorithm = m_acceptedSignatureAlgorithms[i];
                DerInteger reqID = m_acceptedReqIDs[i];

                var digestAlgorithm = m_digestAlgorithmFinder.Find(signatureAlgorithm)
                    ?? throw new CmpException("cannot find algorithm for digest from signature");

                byte[] digest = DigestUtilities.CalculateDigest(digestAlgorithm.Algorithm,
                    cmpCertificate.GetEncoded(Asn1Encodable.Der));

                v.Add(new CertStatus(digest, reqID));
            }

            var content = CertConfirmContent.GetInstance(new DerSequence(v));

            return new CertificateConfirmationContent(content, m_digestAlgorithmFinder);
        }
    }
}
