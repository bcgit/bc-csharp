using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    public class CertificateStatus
    {
        private readonly DefaultDigestAlgorithmIdentifierFinder digestAlgFinder;
        private readonly CertStatus certStatus;

        public CertificateStatus(DefaultDigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus)
        {
            this.digestAlgFinder = digestAlgFinder;
            this.certStatus = certStatus;
        }

        public virtual PkiStatusInfo StatusInfo => certStatus.StatusInfo;

        public virtual BigInteger CertRequestID => certStatus.CertReqID.Value;

        public virtual bool IsVerified(X509Certificate cert)
        {
            var sigAlgID = DefaultSignatureAlgorithmIdentifierFinder.Instance.Find(cert.SigAlgName)
                ?? throw new CmpException("cannot find algorithm identifier for signature name");

            var digAlgID = digestAlgFinder.Find(sigAlgID)
                ?? throw new CmpException("cannot find algorithm for digest from signature " + cert.SigAlgName);

            byte[] digest = DigestUtilities.CalculateDigest(digAlgID.Algorithm, cert.GetEncoded());

            return Arrays.FixedTimeEquals(certStatus.CertHash.GetOctets(), digest);
        }
    }
}
