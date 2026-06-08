using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// Fluent builder for <see cref="Pkcs12Store"/> instances, configuring PBE algorithms and
    /// encoding options used when saving PKCS#12 files (RFC 7292).
    /// </summary>
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

        /// <summary>Creates a builder with library-default PBE algorithms and options.</summary>
        public Pkcs12StoreBuilder()
        {
        }

        /// <summary>
        /// Builds a new <see cref="Pkcs12Store"/> using the configured algorithms and options.
        /// </summary>
        /// <returns>A new, empty PKCS#12 store.</returns>
        public Pkcs12Store Build()
        {
            return new Pkcs12Store(certAlgorithm, certPrfAlgorithm, keyAlgorithm, keyPrfAlgorithm, useDerEncoding,
                reverseCertificates, overwriteFriendlyName, enableOracleTrustedKeyUsage);
        }

        /// <summary>
        /// Sets the PBE algorithm used to encrypt certificate bags when saving (PKCS#12 scheme 1).
        /// </summary>
        /// <param name="certAlgorithm">The certificate encryption algorithm OID.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetCertAlgorithm(DerObjectIdentifier certAlgorithm)
        {
            this.certAlgorithm = certAlgorithm;
            this.certPrfAlgorithm = null;
            return this;
        }

        /// <summary>
        /// Sets the PBES2 algorithm and PRF used to encrypt certificate bags when saving (PKCS#12 scheme 2).
        /// </summary>
        /// <param name="certAlgorithm">The certificate encryption algorithm OID.</param>
        /// <param name="certPrfAlgorithm">The PRF algorithm OID.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetCertAlgorithm(DerObjectIdentifier certAlgorithm,
            DerObjectIdentifier certPrfAlgorithm)
        {
            this.certAlgorithm = certAlgorithm;
            this.certPrfAlgorithm = certPrfAlgorithm;
            return this;
        }

        /// <summary>
        /// Whether to include Oracle's TrustedKeyUsage attribute in CertBag attributes. Defaults to <c>true</c>.
        /// </summary>
        /// <remarks>The OID 2.16.840.1.113894.746875.1.1 is used for this attribute.</remarks>
        /// <param name="enableOracleTrustedKeyUsage"><c>true</c> to emit the attribute when saving.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetEnableOracleTrustedKeyUsage(bool enableOracleTrustedKeyUsage)
        {
            this.enableOracleTrustedKeyUsage = enableOracleTrustedKeyUsage;
            return this;
        }

        /// <summary>
        /// Sets the PBE algorithm used to encrypt private-key bags when saving (PKCS#12 scheme 1).
        /// </summary>
        /// <param name="keyAlgorithm">The key encryption algorithm OID.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetKeyAlgorithm(DerObjectIdentifier keyAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.keyPrfAlgorithm = null;
            return this;
        }

        /// <summary>
        /// Sets the PBES2 algorithm and PRF used to encrypt private-key bags when saving (PKCS#12 scheme 2).
        /// </summary>
        /// <param name="keyAlgorithm">The key encryption algorithm OID.</param>
        /// <param name="keyPrfAlgorithm">The PRF algorithm OID.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetKeyAlgorithm(DerObjectIdentifier keyAlgorithm,
            DerObjectIdentifier keyPrfAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.keyPrfAlgorithm = keyPrfAlgorithm;
            return this;
        }

        /// <summary>
        /// Controls whether <see cref="Pkcs12Store.SetFriendlyName"/> may replace an existing friendly name.
        /// Defaults to <c>true</c>.
        /// </summary>
        /// <param name="overwriteFriendlyName"><c>true</c> to allow overwriting friendly names.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetOverwriteFriendlyName(bool overwriteFriendlyName)
        {
            this.overwriteFriendlyName = overwriteFriendlyName;
            return this;
        }

        /// <summary>
        /// When <c>true</c>, certificate and key bags are written in reverse insertion order when saving.
        /// </summary>
        /// <param name="reverseCertificates"><c>true</c> to reverse bag order on save.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetReverseCertificates(bool reverseCertificates)
        {
            this.reverseCertificates = reverseCertificates;
            return this;
        }

        /// <summary>
        /// When <c>true</c>, saved PKCS#12 structures use DER encoding instead of BER for inner content.
        /// </summary>
        /// <param name="useDerEncoding"><c>true</c> for definite-length DER encoding.</param>
        /// <returns>This builder instance.</returns>
        public Pkcs12StoreBuilder SetUseDerEncoding(bool useDerEncoding)
        {
            this.useDerEncoding = useDerEncoding;
            return this;
        }
    }
}
