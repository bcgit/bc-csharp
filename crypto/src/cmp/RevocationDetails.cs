using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Cmp
{
    public struct RevocationDetails
    {
        private readonly RevDetails m_revDetails;

        public RevocationDetails(RevDetails revDetails)
        {
            m_revDetails = revDetails;
        }

        public X509Name Subject => m_revDetails.CertDetails.Subject;

        public X509Name Issuer => m_revDetails.CertDetails.Issuer;

        public BigInteger SerialNumber => m_revDetails.CertDetails.SerialNumber.Value;

        public RevDetails ToASN1Structure() => m_revDetails;
    }
}
