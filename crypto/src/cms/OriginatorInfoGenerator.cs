using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    public class OriginatorInfoGenerator
    {
        private readonly List<Asn1Encodable> origCerts;
        private readonly List<Asn1Encodable> origCrls;

        public OriginatorInfoGenerator(X509Certificate origCert)
        {
            this.origCerts = new List<Asn1Encodable>{ origCert.CertificateStructure };
            this.origCrls = null;
        }

        public OriginatorInfoGenerator(IStore<X509Certificate> x509Certs)
            : this(x509Certs, null, null, null)
        {
        }

        public OriginatorInfoGenerator(IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls)
            : this(x509Certs, x509Crls, null, null)
        {
        }

        public OriginatorInfoGenerator(IStore<X509Certificate> x509Certs, IStore<X509Crl> x509Crls,
            IStore<X509V2AttributeCertificate> x509AttrCerts, IStore<OtherRevocationInfoFormat> otherRevocationInfos)
        {
            List<Asn1Encodable> certificates = null;
            if (x509Certs != null || x509AttrCerts != null)
            {
                certificates = new List<Asn1Encodable>();
                if (x509Certs != null)
                {
                    certificates.AddRange(CmsUtilities.GetCertificatesFromStore(x509Certs));
                }
                if (x509AttrCerts != null)
                {
                    certificates.AddRange(CmsUtilities.GetAttributeCertificatesFromStore(x509AttrCerts));
                }
            }

            List<Asn1Encodable> revocations = null;
            if (x509Crls != null || otherRevocationInfos != null)
            {
                revocations = new List<Asn1Encodable>();
                if (x509Crls != null)
                {
                    revocations.AddRange(CmsUtilities.GetCrlsFromStore(x509Crls));
                }
                if (otherRevocationInfos != null)
                {
                    revocations.AddRange(CmsUtilities.GetOtherRevocationInfosFromStore(otherRevocationInfos));
                }
            }

            this.origCerts = certificates;
            this.origCrls = revocations;
        }

        public virtual OriginatorInfo Generate()
        {
            Asn1Set certSet = origCerts == null ? null : CmsUtilities.CreateDerSetFromList(origCerts);
            Asn1Set crlSet = origCrls == null ? null : CmsUtilities.CreateDerSetFromList(origCrls);
            return new OriginatorInfo(certSet, crlSet);
        }
    }
}
