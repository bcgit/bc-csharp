using System;
using System.Collections.Generic;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>Base class for a TlsCrypto implementation that provides some needed methods from elsewhere in the impl
    /// package.</summary>
    public abstract class AbstractTlsCrypto
        : TlsCrypto
    {
        /// <inheritdoc/>
        public abstract bool HasAnyStreamVerifiers(IList<SignatureAndHashAlgorithm> signatureAndHashAlgorithms);

        /// <inheritdoc/>
        public abstract bool HasAnyStreamVerifiersLegacy(short[] clientCertificateTypes);

        /// <inheritdoc/>
        public abstract bool HasCryptoHashAlgorithm(int cryptoHashAlgorithm);

        /// <inheritdoc/>
        public abstract bool HasCryptoSignatureAlgorithm(int cryptoSignatureAlgorithm);

        /// <inheritdoc/>
        public abstract bool HasDHAgreement();

        /// <inheritdoc/>
        public abstract bool HasECDHAgreement();

        /// <inheritdoc/>
        public abstract bool HasEncryptionAlgorithm(int encryptionAlgorithm);

        /// <inheritdoc/>
        public abstract bool HasHkdfAlgorithm(int cryptoHashAlgorithm);

        /// <inheritdoc/>
        public abstract bool HasKemAgreement();

        /// <inheritdoc/>
        public abstract bool HasMacAlgorithm(int macAlgorithm);

        /// <inheritdoc/>
        public abstract bool HasNamedGroup(int namedGroup);

        /// <inheritdoc/>
        public abstract bool HasRsaEncryption();

        /// <inheritdoc/>
        public abstract bool HasSignatureAlgorithm(short signatureAlgorithm);

        /// <inheritdoc/>
        public abstract bool HasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm);

        /// <inheritdoc/>
        public abstract bool HasSignatureScheme(int signatureScheme);

        /// <inheritdoc/>
        public abstract bool HasSrpAuthentication();

        /// <inheritdoc/>
        public abstract TlsSecret CreateHybridSecret(TlsSecret s1, TlsSecret s2);

        /// <inheritdoc/>
        public abstract TlsSecret CreateSecret(byte[] data);

        /// <inheritdoc/>
        public abstract TlsSecret GenerateRsaPreMasterSecret(ProtocolVersion clientVersion);

        /// <summary>Gets the source of randomness used by this crypto.</summary>
        public abstract SecureRandom SecureRandom { get; }

        /// <inheritdoc/>
        public virtual TlsCertificate CreateCertificate(byte[] encoding)
        {
            return CreateCertificate(CertificateType.X509, encoding);
        }

        /// <inheritdoc/>
        public abstract TlsCertificate CreateCertificate(short type, byte[] encoding);

        /// <inheritdoc/>
        public abstract TlsCipher CreateCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm);

        /// <inheritdoc/>
        public abstract TlsDHDomain CreateDHDomain(TlsDHConfig dhConfig);

        /// <inheritdoc/>
        public abstract TlsECDomain CreateECDomain(TlsECConfig ecConfig);

        /// <inheritdoc/>
        public abstract TlsKemDomain CreateKemDomain(TlsKemConfig kemConfig);

        /// <inheritdoc/>
        public virtual TlsSecret AdoptSecret(TlsSecret secret)
        {
            // TODO[tls] Need an alternative that doesn't require AbstractTlsSecret (which holds literal data)
            if (secret is AbstractTlsSecret abstractTlsSecret)
                return CreateSecret(abstractTlsSecret.CopyData());

            throw new ArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.GetType().FullName);
        }

        /// <inheritdoc/>
        public abstract TlsHash CreateHash(int cryptoHashAlgorithm);

        /// <inheritdoc/>
        public abstract TlsHmac CreateHmac(int macAlgorithm);

        /// <inheritdoc/>
        public abstract TlsHmac CreateHmacForHash(int cryptoHashAlgorithm);

        /// <inheritdoc/>
        public abstract TlsNonceGenerator CreateNonceGenerator(byte[] additionalSeedMaterial);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public abstract TlsNonceGenerator CreateNonceGenerator(ReadOnlySpan<byte> additionalSeedMaterial);
#endif

        /// <inheritdoc/>
        public abstract TlsSrp6Client CreateSrp6Client(TlsSrpConfig srpConfig);

        /// <inheritdoc/>
        public abstract TlsSrp6Server CreateSrp6Server(TlsSrpConfig srpConfig, BigInteger srpVerifier);

        /// <inheritdoc/>
        public abstract TlsSrp6VerifierGenerator CreateSrp6VerifierGenerator(TlsSrpConfig srpConfig);

        /// <inheritdoc/>
        public abstract TlsSecret HkdfInit(int cryptoHashAlgorithm);
    }
}
