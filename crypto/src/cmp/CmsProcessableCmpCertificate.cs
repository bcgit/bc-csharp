using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cmp
{
    /// <summary>Carrier class for a <see cref="CmpCertificate"/> over CMS.</summary>
    public sealed class CmsProcessableCmpCertificate
        : CmsTypedData
    {
        private readonly CmpCertificate m_cmpCertificate;

        public CmsProcessableCmpCertificate(X509Certificate certificate)
            : this(new CmpCertificate(certificate.CertificateStructure))
        {
        }

        public CmsProcessableCmpCertificate(CmpCertificate cmpCertificate)
        {
            m_cmpCertificate = cmpCertificate ?? throw new ArgumentNullException(nameof(cmpCertificate));
        }

        public void Write(Stream outStream)
        {
            m_cmpCertificate.EncodeTo(outStream);
        }

        public DerObjectIdentifier ContentType => PkcsObjectIdentifiers.Data;
    }
}
