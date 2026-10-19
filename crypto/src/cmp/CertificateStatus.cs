using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>The confirmation status of a single certificate within a certificate confirmation message.</summary>
    public class CertificateStatus
    {
        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;
        private readonly CertStatus m_certStatus;

        [Obsolete("Use constructor taking 'IDigestAlgorithmFinder' instead")]
        public CertificateStatus(Cms.DefaultDigestAlgorithmIdentifierFinder digestAlgFinder,
            CertStatus certStatus)
            : this((IDigestAlgorithmFinder)digestAlgFinder, certStatus)
        {
        }

        /// <summary>Wrap a CertStatus structure.</summary>
        /// <param name="digestAlgorithmFinder">Finds the digest algorithm matching a signature algorithm.</param>
        /// <param name="certStatus">The ASN.1 structure.</param>
        public CertificateStatus(IDigestAlgorithmFinder digestAlgorithmFinder, CertStatus certStatus)
        {
            m_digestAlgorithmFinder = digestAlgorithmFinder;
            m_certStatus = certStatus;
        }

        /// <summary>Gets the status information, or null if there is none.</summary>
        public virtual PkiStatusInfo StatusInfo => m_certStatus.StatusInfo;

        /// <summary>Gets the identifier of the certificate request this status relates to.</summary>
        public virtual DerInteger CertReqID => m_certStatus.CertReqID;

        [Obsolete("Use 'CertReqID' instead")]
        public virtual BigInteger CertRequestID => m_certStatus.CertReqID.Value;

        /// <summary>Return whether the certificate matches the hash in this status.</summary>
        /// <param name="cert">The certificate to check.</param>
        /// <returns>true if the certificate hash matches.</returns>
        /// <exception cref="CmpException">No digest algorithm can be found for the signature algorithm.</exception>
        public virtual bool IsVerified(X509Certificate cert) =>
            IsVerified(new CmpCertificate(cert.CertificateStructure), cert.SignatureAlgorithm);

        /// <summary>Return whether the certificate matches the hash in this status.</summary>
        /// <param name="cmpCertificate">The certificate to check.</param>
        /// <param name="signatureAlgorithm">The algorithm the certificate was signed with.</param>
        /// <returns>true if the certificate hash matches.</returns>
        /// <exception cref="CmpException">No digest algorithm can be found for the signature algorithm.</exception>
        public virtual bool IsVerified(CmpCertificate cmpCertificate, AlgorithmIdentifier signatureAlgorithm)
        {
            var certHash = CmpUtilities.CalculateCertHash(cmpCertificate, signatureAlgorithm, m_certStatus.HashAlg,
                m_digestAlgorithmFinder);

            return Arrays.FixedTimeEquals(m_certStatus.CertHash.GetOctets(), certHash);
        }
    }
}
