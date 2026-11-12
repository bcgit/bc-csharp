using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>Builder for <see cref="CertificateConfirmationContent"/>.</summary>
    /// <remarks>
    /// Add each accepted certificate with <c>AddAcceptedCertificate</c>, then call <see cref="Build"/>.
    /// </remarks>
    public sealed class CertificateConfirmationContentBuilder
    {
        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;
        private readonly List<CmpCertificate> m_acceptedCerts = new List<CmpCertificate>();
        private readonly List<AlgorithmIdentifier> m_acceptedSignatureAlgorithms = new List<AlgorithmIdentifier>();
        private readonly List<DerInteger> m_acceptedReqIDs = new List<DerInteger>();

        /// <summary>Create a builder using the default digest algorithm finder.</summary>
        public CertificateConfirmationContentBuilder()
            : this(DefaultDigestAlgorithmFinder.Instance)
        {
        }

        /// <summary>Create a new <see cref="CertificateConfirmationContentBuilder"/>.</summary>
        /// <param name="digestAlgFinder">The digest alg finder.</param>
        [Obsolete("Use constructor taking 'IDigestAlgorithmFinder' instead")]
        public CertificateConfirmationContentBuilder(Cms.DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
            : this((IDigestAlgorithmFinder)digestAlgFinder)
        {
        }

        /// <summary>Create a builder.</summary>
        /// <param name="digestAlgorithmFinder">Finds the digest algorithm matching a signature algorithm.</param>
        public CertificateConfirmationContentBuilder(IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            m_digestAlgorithmFinder = digestAlgorithmFinder;
        }

        /// <summary>Add an accepted certificate.</summary>
        /// <param name="certHolder">The accepted certificate.</param>
        /// <param name="certReqId">The identifier of the certificate request that led to the certificate.</param>
        /// <returns>This builder.</returns>
        // TODO[api] Rename parameters to 'cert', 'certReqID'
        public CertificateConfirmationContentBuilder AddAcceptedCertificate(X509Certificate certHolder,
            BigInteger certReqId)
        {
            return AddAcceptedCertificate(certHolder, new DerInteger(certReqId));
        }

        /// <summary>Add an accepted certificate.</summary>
        /// <param name="cert">The accepted certificate.</param>
        /// <param name="certReqID">The identifier of the certificate request that led to the certificate.</param>
        /// <returns>This builder.</returns>
        public CertificateConfirmationContentBuilder AddAcceptedCertificate(X509Certificate cert, DerInteger certReqID)
        {
            return AddAcceptedCertificate(
                new CmpCertificate(cert.CertificateStructure), cert.SignatureAlgorithm, certReqID);
        }

        /// <summary>Add an accepted certificate.</summary>
        /// <param name="cmpCertificate">The accepted certificate.</param>
        /// <param name="signatureAlgorithm">The algorithm the certificate was signed with.</param>
        /// <param name="certReqID">The identifier of the certificate request that led to the certificate.</param>
        /// <returns>This builder.</returns>
        public CertificateConfirmationContentBuilder AddAcceptedCertificate(CmpCertificate cmpCertificate,
            AlgorithmIdentifier signatureAlgorithm, DerInteger certReqID)
        {
            m_acceptedCerts.Add(cmpCertificate);
            m_acceptedSignatureAlgorithms.Add(signatureAlgorithm);
            m_acceptedReqIDs.Add(certReqID);

            return this;
        }

        /// <summary>Build the content, hashing each accepted certificate.</summary>
        /// <exception cref="CmpException">No digest algorithm can be found for a certificate's signature algorithm.
        /// </exception>
        public CertificateConfirmationContent Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(m_acceptedCerts.Count);
            for (int i = 0; i != m_acceptedCerts.Count; i++)
            {
                var certHash = CmpUtilities.CalculateCertHash(m_acceptedCerts[i], m_acceptedSignatureAlgorithms[i],
                    hashAlg: null, m_digestAlgorithmFinder);
                var reqID = m_acceptedReqIDs[i];

                v.Add(new CertStatus(certHash, reqID));
            }

            var content = CertConfirmContent.GetInstance(new DerSequence(v));

            return new CertificateConfirmationContent(content, m_digestAlgorithmFinder);
        }
    }
}
