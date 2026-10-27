using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.X509
{
    /// <remarks>
    /// This class contains a cross certificate pair. Cross certificates pairs may
    /// contain two cross signed certificates from two CAs. A certificate from the
    /// other CA to this CA is contained in the forward certificate, the certificate
    /// from this CA to the other CA is contained in the reverse certificate.
    /// </remarks>
    public class X509CertificatePair
    {
        private readonly X509Certificate m_forward;
        private readonly X509Certificate m_reverse;

        /// <summary>Constructor</summary>
        /// <param name="forward">Certificate from the other CA to this CA.</param>
        /// <param name="reverse">Certificate from this CA to the other CA.</param>
        public X509CertificatePair(X509Certificate forward, X509Certificate reverse)
        {
            if (forward == null && reverse == null)
                throw new ArgumentException("At least one of the pair shall be present");

            m_forward = forward;
            m_reverse = reverse;
        }

        /// <summary>Constructor from a ASN.1 CertificatePair structure.</summary>
        /// <param name="pair">The <c>CertificatePair</c> ASN.1 object.</param>
        public X509CertificatePair(CertificatePair pair)
        {
            var forward = pair.Forward;
            var reverse = pair.Reverse;

            m_forward = forward == null ? null : new X509Certificate(forward);
            m_reverse = reverse == null ? null : new X509Certificate(reverse);
        }

        /// <summary>Return the ASN.1 CertificatePair structure for the pair.</summary>
        public CertificatePair GetCertificatePair() =>
            new CertificatePair(m_forward?.CertificateStructure, m_reverse?.CertificateStructure);

        /// <summary>Return the DER encoding of the pair.</summary>
        /// <exception cref="CertificateEncodingException">The pair could not be encoded.</exception>
        public byte[] GetEncoded()
        {
            try
            {
                return GetCertificatePair().GetEncoded(Asn1Encodable.Der);
            }
            catch (Exception e)
            {
                throw new CertificateEncodingException(e.Message, e);
            }
        }

        /// <summary>Returns the certificate from the other CA to this CA.</summary>
        public X509Certificate Forward => m_forward;

        /// <summary>Returns the certificate from this CA to the other CA.</summary>
        public X509Certificate Reverse => m_reverse;

        /// <summary>Two pairs are equal if their forward and reverse certificates are equal.</summary>
        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is X509CertificatePair that
                && Objects.Equals(this.m_forward, that.m_forward)
                && Objects.Equals(this.m_reverse, that.m_reverse);
        }

        /// <summary>Returns a hash code derived from the forward and reverse certificates.</summary>
        public override int GetHashCode()
        {
            int hash = -1;
            if (m_forward != null)
            {
                hash ^= m_forward.GetHashCode();
            }
            if (m_reverse != null)
            {
                hash *= 17;
                hash ^= m_reverse.GetHashCode();
            }
            return hash;
        }
    }
}
