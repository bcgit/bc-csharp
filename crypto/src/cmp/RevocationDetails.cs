using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>The details of a certificate to be revoked in a CMP revocation request.</summary>
    public struct RevocationDetails
    {
        private readonly RevDetails m_revDetails;

        /// <summary>Wrap a RevDetails structure.</summary>
        /// <param name="revDetails">The ASN.1 structure.</param>
        public RevocationDetails(RevDetails revDetails)
        {
            m_revDetails = revDetails;
        }

        /// <summary>Gets the subject of the certificate to be revoked.</summary>
        public X509Name Subject => m_revDetails.CertDetails.Subject;

        /// <summary>Gets the issuer of the certificate to be revoked.</summary>
        public X509Name Issuer => m_revDetails.CertDetails.Issuer;

        /// <summary>Gets the serial number of the certificate to be revoked.</summary>
        public BigInteger SerialNumber => m_revDetails.CertDetails.SerialNumber.Value;

        /// <summary>Return the underlying ASN.1 structure.</summary>
        // TODO[api] Rename to 'ToAsn1Structure'
        public RevDetails ToASN1Structure() => m_revDetails;
    }
}
