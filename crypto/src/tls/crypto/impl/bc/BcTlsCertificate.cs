using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for a single X.509 certificate based on the BC light-weight API.</summary>
    public class BcTlsCertificate
        : BcTlsRawKeyCertificate
    {
        /// <exception cref="IOException"/>
        public static BcTlsCertificate Convert(BcTlsCrypto crypto, TlsCertificate certificate)
        {
            if (certificate is BcTlsCertificate)
                return (BcTlsCertificate)certificate;

            return new BcTlsCertificate(crypto, certificate.GetEncoded());
        }

        /// <exception cref="IOException"/>
        public static X509CertificateStructure ParseCertificate(byte[] encoding)
        {
            try
            {
                Asn1Object asn1 = TlsUtilities.ReadAsn1Object(encoding);
                return X509CertificateStructure.GetInstance(asn1);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
            }
        }

        protected readonly X509CertificateStructure m_certificate;

        /// <exception cref="IOException"/>
        public BcTlsCertificate(BcTlsCrypto crypto, byte[] encoding)
            : this(crypto, ParseCertificate(encoding))
        {
        }

        public BcTlsCertificate(BcTlsCrypto crypto, X509CertificateStructure certificate)
            : base(crypto, certificate.SubjectPublicKeyInfo)
        {
            m_certificate = certificate;
        }

        public virtual X509CertificateStructure X509CertificateStructure => m_certificate;

        /// <exception cref="IOException"/>
        public override byte[] GetEncoded()
        {
            return m_certificate.GetEncoded(Asn1Encodable.Der);
        }

        /// <exception cref="IOException"/>
        public override byte[] GetExtension(DerObjectIdentifier extensionOid)
        {
            X509Extensions extensions = m_certificate.TbsCertificate.Extensions;
            if (extensions != null)
            {
                X509Extension extension = extensions.GetExtension(extensionOid);
                if (extension != null)
                {
                    return Arrays.Clone(extension.Value.GetOctets());
                }
            }
            return null;
        }

        public override BigInteger SerialNumber => m_certificate.SerialNumber.Value;

        public override string SigAlgOid => m_certificate.SignatureAlgorithm.Algorithm.Id;

        public override Asn1Encodable GetSigAlgParams() => m_certificate.SignatureAlgorithm.Parameters;

        protected override bool SupportsKeyUsage(int keyUsageBits)
        {
            X509Extensions exts = m_certificate.TbsCertificate.Extensions;
            if (exts != null)
            {
                KeyUsage ku = KeyUsage.FromExtensions(exts);
                if (ku != null)
                {
                    int bits = ku.GetBytes()[0] & 0xff;
                    if ((bits & keyUsageBits) != keyUsageBits)
                        return false;
                }
            }
            return true;
        }
    }
}
