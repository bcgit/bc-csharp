using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
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

        public CertificateStatus(IDigestAlgorithmFinder digestAlgorithmFinder, CertStatus certStatus)
        {
            m_digestAlgorithmFinder = digestAlgorithmFinder;
            m_certStatus = certStatus;
        }

        public virtual PkiStatusInfo StatusInfo => m_certStatus.StatusInfo;

        public virtual BigInteger CertRequestID => m_certStatus.CertReqID.Value;

        public virtual bool IsVerified(X509Certificate cert) =>
            IsVerified(new CmpCertificate(cert.CertificateStructure), cert.SignatureAlgorithm);

        public virtual bool IsVerified(CmpCertificate cmpCertificate, AlgorithmIdentifier signatureAlgorithm)
        {
            AlgorithmIdentifier digestAlgorithm = m_digestAlgorithmFinder.Find(signatureAlgorithm)
                ?? throw new CmpException("cannot find algorithm for digest from signature");

            byte[] digest = DigestUtilities.CalculateDigest(digestAlgorithm.Algorithm,
                cmpCertificate.GetEncoded(Asn1Encodable.Der));

            return Arrays.FixedTimeEquals(m_certStatus.CertHash.GetOctets(), digest);
        }
    }
}
