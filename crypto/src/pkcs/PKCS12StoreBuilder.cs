using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Pkcs
{
    // TODO[api] Make sealed
    public class Pkcs12StoreBuilder
    {
        // TODO[api] Change default to a PBES2 algorithm
        private DerObjectIdentifier certAlgorithm = PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc;
        private DerObjectIdentifier certPrfAlgorithm = null;

        // TODO[api] Change default to a PBES2 algorithm
        private DerObjectIdentifier keyAlgorithm = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;
        private DerObjectIdentifier keyPrfAlgorithm = null;

        private bool useDerEncoding = false;
        private bool reverseCertificates = false;
        private bool overwriteFriendlyName = true;
        private bool enableOracleTrustedKeyUsage = true;

        public Pkcs12StoreBuilder()
        {
        }

        public Pkcs12Store Build()
        {
            return new Pkcs12Store(certAlgorithm, certPrfAlgorithm, keyAlgorithm, keyPrfAlgorithm, useDerEncoding,
                reverseCertificates, overwriteFriendlyName, enableOracleTrustedKeyUsage);
        }

        public Pkcs12StoreBuilder SetCertAlgorithm(DerObjectIdentifier certAlgorithm)
        {
            this.certAlgorithm = certAlgorithm;
            this.certPrfAlgorithm = null;
            return this;
        }

        // Specify a PKCS#5 Scheme 2 encryption for certs
        public Pkcs12StoreBuilder SetCertAlgorithm(DerObjectIdentifier certAlgorithm, DerObjectIdentifier certPrfAlgorithm)
        {
            this.certAlgorithm = certAlgorithm;
            this.certPrfAlgorithm = certPrfAlgorithm;
            return this;
        }

        /// <summary>
        /// Whether to include Oracle's TrustedKeyUsage attribute in CertBag attributes. Defaults to <c>true</c>.
        /// </summary>
        /// <remarks>The OID 2.16.840.1.113894.746875.1.1 is used for this attribute.</remarks>
        /// <param name="enableOracleTrustedKeyUsage"></param>
        /// <returns></returns>
        public Pkcs12StoreBuilder SetEnableOracleTrustedKeyUsage(bool enableOracleTrustedKeyUsage)
        {
            this.enableOracleTrustedKeyUsage = enableOracleTrustedKeyUsage;
            return this;
        }

        public Pkcs12StoreBuilder SetKeyAlgorithm(DerObjectIdentifier keyAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.keyPrfAlgorithm = null;
            return this;
        }

        // Specify a PKCS#5 Scheme 2 encryption for keys
        public Pkcs12StoreBuilder SetKeyAlgorithm(DerObjectIdentifier keyAlgorithm, DerObjectIdentifier keyPrfAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.keyPrfAlgorithm = keyPrfAlgorithm;
            return this;
        }

        public Pkcs12StoreBuilder SetOverwriteFriendlyName(bool overwriteFriendlyName)
        {
            this.overwriteFriendlyName = overwriteFriendlyName;
            return this;
        }

        public Pkcs12StoreBuilder SetReverseCertificates(bool reverseCertificates)
        {
            this.reverseCertificates = reverseCertificates;
            return this;
        }

        public Pkcs12StoreBuilder SetUseDerEncoding(bool useDerEncoding)
        {
            this.useDerEncoding = useDerEncoding;
            return this;
        }
    }
}
