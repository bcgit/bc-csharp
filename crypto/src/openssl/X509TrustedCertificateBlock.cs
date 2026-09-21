using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>Holder for an OpenSSL trusted certificate block.</summary>
    public class X509TrustedCertificateBlock
    {
        private readonly X509Certificate m_certificate;
        private readonly CertificateTrustBlock m_trustBlock;

        public X509TrustedCertificateBlock(X509Certificate certificate, CertificateTrustBlock trustBlock)
        {
            m_certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            m_trustBlock = trustBlock;
        }

        public X509TrustedCertificateBlock(byte[] encoding)
        {
            using (var asn1 = new Asn1InputStream(encoding))
            {
                m_certificate = new X509Certificate(X509CertificateStructure.GetInstance(asn1.ReadObject()));

                var trustBlock = asn1.ReadObject();
                m_trustBlock = trustBlock == null ? null : new CertificateTrustBlock(trustBlock.GetEncoded());
            }
        }

        public byte[] GetEncoded() =>
            Arrays.Concatenate(m_certificate.GetEncoded(), m_trustBlock.ToAsn1Sequence().GetEncoded());

        public X509Certificate Certificate => m_certificate;

        public CertificateTrustBlock TrustBlock => m_trustBlock;
    }
}
