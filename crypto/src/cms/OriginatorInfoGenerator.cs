using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Builds CMS <c>OriginatorInfo</c> values carrying certificates and revocation information for authenticated
    /// messages. The read-side wrapper is <see cref="OriginatorInformation"/>.
    /// </summary>
    public class OriginatorInfoGenerator
    {
        private readonly List<Asn1Encodable> origCerts;
        private readonly List<Asn1Encodable> origCrls;

        /// <summary>Creates a generator containing a single originator certificate.</summary>
        /// <param name="origCert">The originator's X.509 certificate.</param>
        public OriginatorInfoGenerator(X509Certificate origCert)
        {
            this.origCerts = new List<Asn1Encodable>{ origCert.CertificateStructure };
            this.origCrls = null;
        }

        /// <summary>Creates a generator from a store of originator certificates.</summary>
        /// <param name="x509Certs">Public-key certificates to include, or null to omit.</param>
        public OriginatorInfoGenerator(IStore<X509Certificate> x509Certs)
            : this(x509Certs, null, null, null)
        {
        }

        /// <summary>Creates a generator from certificate and CRL stores.</summary>
        /// <param name="x509Certs">Public-key certificates to include, or null to omit.</param>
        /// <param name="x509Crls">CRLs to include, or null to omit.</param>
        public OriginatorInfoGenerator(IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls)
            : this(x509Certs, x509Crls, null, null)
        {
        }

        /// <summary>
        /// Creates a generator from certificate, CRL, attribute-certificate, and other-revocation stores.
        /// </summary>
        /// <param name="x509Certs">Public-key certificates to include, or null to omit.</param>
        /// <param name="x509Crls">CRLs to include, or null to omit.</param>
        /// <param name="x509AttrCerts">Attribute certificates to include, or null to omit.</param>
        /// <param name="otherRevocationInfos">Other revocation information to include, or null to omit.</param>
        public OriginatorInfoGenerator(IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls,
            IStore<X509V2AttributeCertificate> x509AttrCerts, IStore<OtherRevocationInfoFormat> otherRevocationInfos)
        {
            List<Asn1Encodable> certificates = null;
            if (x509Certs != null || x509AttrCerts != null)
            {
                certificates = new List<Asn1Encodable>();
                if (x509Certs != null)
                {
                    CmsUtilities.CollectCertificates(certificates, x509Certs);
                }
                if (x509AttrCerts != null)
                {
                    CmsUtilities.CollectAttributeCertificates(certificates, x509AttrCerts);
                }
            }

            List<Asn1Encodable> revocations = null;
            if (x509Crls != null || otherRevocationInfos != null)
            {
                revocations = new List<Asn1Encodable>();
                if (x509Crls != null)
                {
                    CmsUtilities.CollectCrls(revocations, x509Crls);
                }
                if (otherRevocationInfos != null)
                {
                    CmsUtilities.CollectOtherRevocationInfos(revocations, otherRevocationInfos);
                }
            }

            this.origCerts = certificates;
            this.origCrls = revocations;
        }

        /// <summary>Builds an OriginatorInfo structure from the configured stores.</summary>
        /// <returns>A CMS OriginatorInfo value.</returns>
        public virtual OriginatorInfo Generate() => new OriginatorInfo(origCerts?.ToDerSet(), origCrls?.ToDerSet());
    }
}
