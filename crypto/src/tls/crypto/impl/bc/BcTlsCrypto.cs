using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /**
     * Class for providing cryptographic services for TLS based on implementations in the BC light-weight API.
     * <p>
     *     This class provides default implementations for everything. If you need to customise it, extend the class
     *     and override the appropriate methods.
     * </p>
     */
    public class BcTlsCrypto
        : AbstractTlsCrypto
    {
        private readonly SecureRandom m_entropySource;

        /// <summary>Create a new <see cref="BcTlsCrypto"/>.</summary>
        public BcTlsCrypto()
            : this(CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>Create a new <see cref="BcTlsCrypto"/>.</summary>
        /// <param name="entropySource">The entropy source.</param>
        public BcTlsCrypto(SecureRandom entropySource)
        {
            if (entropySource == null)
                throw new ArgumentNullException(nameof(entropySource));

            this.m_entropySource = entropySource;
        }

        internal virtual BcTlsSecret AdoptLocalSecret(byte[] data)
        {
            return new BcTlsSecret(this, data);
        }

        /// <summary>Gets the source of randomness used by this crypto.</summary>
        public override SecureRandom SecureRandom
        {
            get { return m_entropySource; }
        }

        /// <inheritdoc/>
        public override TlsCertificate CreateCertificate(short type, byte[] encoding)
        {
            switch (type)
            {
            case CertificateType.X509:
                return new BcTlsCertificate(this, encoding);
            case CertificateType.RawPublicKey:
                return new BcTlsRawKeyCertificate(this, encoding);
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /// <inheritdoc/>
        public override TlsCipher CreateCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm,
            int macAlgorithm)
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.AES_128_CBC:
            case EncryptionAlgorithm.ARIA_128_CBC:
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
            case EncryptionAlgorithm.SEED_CBC:
            case EncryptionAlgorithm.SM4_CBC:
                return CreateCipher_Cbc(cryptoParams, encryptionAlgorithm, 16, macAlgorithm);

            case EncryptionAlgorithm.cls_3DES_EDE_CBC:
                return CreateCipher_Cbc(cryptoParams, encryptionAlgorithm, 24, macAlgorithm);

            case EncryptionAlgorithm.AES_256_CBC:
            case EncryptionAlgorithm.ARIA_256_CBC:
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
                return CreateCipher_Cbc(cryptoParams, encryptionAlgorithm, 32, macAlgorithm);

            case EncryptionAlgorithm.AES_128_CCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aes_Ccm(cryptoParams, 16, 16);
            case EncryptionAlgorithm.AES_128_CCM_8:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aes_Ccm(cryptoParams, 16, 8);
            case EncryptionAlgorithm.AES_128_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aes_Gcm(cryptoParams, 16, 16);
            case EncryptionAlgorithm.AES_256_CCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aes_Ccm(cryptoParams, 32, 16);
            case EncryptionAlgorithm.AES_256_CCM_8:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aes_Ccm(cryptoParams, 32, 8);
            case EncryptionAlgorithm.AES_256_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aes_Gcm(cryptoParams, 32, 16);
            case EncryptionAlgorithm.ARIA_128_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aria_Gcm(cryptoParams, 16, 16);
            case EncryptionAlgorithm.ARIA_256_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Aria_Gcm(cryptoParams, 32, 16);
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Camellia_Gcm(cryptoParams, 16, 16);
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_Camellia_Gcm(cryptoParams, 32, 16);
            case EncryptionAlgorithm.CHACHA20_POLY1305:
                // NOTE: Ignores macAlgorithm
                return CreateChaCha20Poly1305(cryptoParams);
            case EncryptionAlgorithm.NULL:
                return CreateNullCipher(cryptoParams, macAlgorithm);
            case EncryptionAlgorithm.NULL_HMAC_SHA256:
                // NOTE: Ignores macAlgorithm
                return Create13NullCipher(cryptoParams, MacAlgorithm.hmac_sha256);
            case EncryptionAlgorithm.NULL_HMAC_SHA384:
                // NOTE: Ignores macAlgorithm
                return Create13NullCipher(cryptoParams, MacAlgorithm.hmac_sha384);
            case EncryptionAlgorithm.SM4_CCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_SM4_Ccm(cryptoParams);
            case EncryptionAlgorithm.SM4_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateCipher_SM4_Gcm(cryptoParams);

            case EncryptionAlgorithm.cls_28147_CNT_IMIT:
            case EncryptionAlgorithm.DES40_CBC:
            case EncryptionAlgorithm.DES_CBC:
            case EncryptionAlgorithm.IDEA_CBC:
            case EncryptionAlgorithm.KUZNYECHIK_CTR_OMAC:
            case EncryptionAlgorithm.MAGMA_CTR_OMAC:
            case EncryptionAlgorithm.RC2_CBC_40:
            case EncryptionAlgorithm.RC4_128:
            case EncryptionAlgorithm.RC4_40:
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /// <inheritdoc/>
        public override TlsDHDomain CreateDHDomain(TlsDHConfig dhConfig)
        {
            return new BcTlsDHDomain(this, dhConfig);
        }

        /// <inheritdoc/>
        public override TlsECDomain CreateECDomain(TlsECConfig ecConfig)
        {
            switch (ecConfig.NamedGroup)
            {
            case NamedGroup.x25519:
                return new BcX25519Domain(this);
            case NamedGroup.x448:
                return new BcX448Domain(this);
            default:
                return new BcTlsECDomain(this, ecConfig);
            }
        }

        /// <inheritdoc/>
        public override TlsKemDomain CreateKemDomain(TlsKemConfig kemConfig)
        {
            return new BcTlsMLKemDomain(this, kemConfig);
        }

        /// <inheritdoc/>
        public override TlsNonceGenerator CreateNonceGenerator(byte[] additionalSeedMaterial)
        {
            // TODO[api] Require non-null additionalSeedMaterial
            //if (additionalSeedMaterial == null)
            //    throw new ArgumentNullException(nameof(additionalSeedMaterial));

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            var seed = additionalSeedMaterial == null ? Span<byte>.Empty : additionalSeedMaterial.AsSpan();

            return CreateNonceGenerator(seed);
#else
            int cryptoHashAlgorithm = CryptoHashAlgorithm.sha256;
            IDigest digest = CreateDigest(cryptoHashAlgorithm);

            int seedLength = 2 * TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm);
            byte[] seed = new byte[seedLength];
            SecureRandom.NextBytes(seed);

            DigestRandomGenerator randomGenerator = new DigestRandomGenerator(digest);
            randomGenerator.AddSeedMaterial(additionalSeedMaterial);
            randomGenerator.AddSeedMaterial(seed);

            return new BcTlsNonceGenerator(randomGenerator);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override TlsNonceGenerator CreateNonceGenerator(ReadOnlySpan<byte> additionalSeedMaterial)
        {
            int cryptoHashAlgorithm = CryptoHashAlgorithm.sha256;
            IDigest digest = CreateDigest(cryptoHashAlgorithm);

            int seedLength = 2 * TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm);
            Span<byte> seed = seedLength <= 128
                ? stackalloc byte[seedLength]
                : new byte[seedLength];
            SecureRandom.NextBytes(seed);

            DigestRandomGenerator randomGenerator = new DigestRandomGenerator(digest);
            randomGenerator.AddSeedMaterial(additionalSeedMaterial);
            randomGenerator.AddSeedMaterial(seed);

            return new BcTlsNonceGenerator(randomGenerator);
        }
#endif

        /// <inheritdoc/>
        public override bool HasAnyStreamVerifiers(IList<SignatureAndHashAlgorithm> signatureAndHashAlgorithms)
        {
            foreach (SignatureAndHashAlgorithm algorithm in signatureAndHashAlgorithms)
            {
                switch (SignatureScheme.From(algorithm))
                {
                case SignatureScheme.ed25519:
                case SignatureScheme.ed448:
                    return true;
                }
            }
            return false;
        }

        /// <inheritdoc/>
        public override bool HasAnyStreamVerifiersLegacy(short[] clientCertificateTypes)
        {
            return false;
        }

        /// <inheritdoc/>
        public override bool HasCryptoHashAlgorithm(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.md5:
            case CryptoHashAlgorithm.sha1:
            case CryptoHashAlgorithm.sha224:
            case CryptoHashAlgorithm.sha256:
            case CryptoHashAlgorithm.sha384:
            case CryptoHashAlgorithm.sha512:
            case CryptoHashAlgorithm.sm3:
            case CryptoHashAlgorithm.gostr3411_2012_256:
                return true;

            default:
                return false;
            }
        }

        /// <inheritdoc/>
        public override bool HasCryptoSignatureAlgorithm(int cryptoSignatureAlgorithm)
        {
            switch (cryptoSignatureAlgorithm)
            {
            case CryptoSignatureAlgorithm.rsa:
            case CryptoSignatureAlgorithm.dsa:
            case CryptoSignatureAlgorithm.ecdsa:
            case CryptoSignatureAlgorithm.rsa_pss_rsae_sha256:
            case CryptoSignatureAlgorithm.rsa_pss_rsae_sha384:
            case CryptoSignatureAlgorithm.rsa_pss_rsae_sha512:
            case CryptoSignatureAlgorithm.ed25519:
            case CryptoSignatureAlgorithm.ed448:
            case CryptoSignatureAlgorithm.rsa_pss_pss_sha256:
            case CryptoSignatureAlgorithm.rsa_pss_pss_sha384:
            case CryptoSignatureAlgorithm.rsa_pss_pss_sha512:
            case CryptoSignatureAlgorithm.sm2: // RFC 8998
                return true;

            // TODO[RFC 9189]
            case CryptoSignatureAlgorithm.gostr34102012_256:
            case CryptoSignatureAlgorithm.gostr34102012_512:

            default:
                return false;
            }
        }

        /// <inheritdoc/>
        public override bool HasDHAgreement()
        {
            return true;
        }

        /// <inheritdoc/>
        public override bool HasECDHAgreement()
        {
            return true;
        }

        /// <inheritdoc/>
        public override bool HasEncryptionAlgorithm(int encryptionAlgorithm)
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.AES_128_CBC:
            case EncryptionAlgorithm.AES_128_CCM:
            case EncryptionAlgorithm.AES_128_CCM_8:
            case EncryptionAlgorithm.AES_128_GCM:
            case EncryptionAlgorithm.AES_256_CBC:
            case EncryptionAlgorithm.AES_256_CCM:
            case EncryptionAlgorithm.AES_256_CCM_8:
            case EncryptionAlgorithm.AES_256_GCM:
            case EncryptionAlgorithm.ARIA_128_CBC:
            case EncryptionAlgorithm.ARIA_128_GCM:
            case EncryptionAlgorithm.ARIA_256_CBC:
            case EncryptionAlgorithm.ARIA_256_GCM:
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
            case EncryptionAlgorithm.CHACHA20_POLY1305:
            case EncryptionAlgorithm.cls_3DES_EDE_CBC:
            case EncryptionAlgorithm.NULL:
            case EncryptionAlgorithm.SEED_CBC:
            case EncryptionAlgorithm.SM4_CBC:
            case EncryptionAlgorithm.SM4_CCM:
            case EncryptionAlgorithm.SM4_GCM:
                return true;

            case EncryptionAlgorithm.NULL_HMAC_SHA256:
                return HasMacAlgorithm(MacAlgorithm.hmac_sha256);

            case EncryptionAlgorithm.NULL_HMAC_SHA384:
                return HasMacAlgorithm(MacAlgorithm.hmac_sha384);

            case EncryptionAlgorithm.cls_28147_CNT_IMIT:
            case EncryptionAlgorithm.DES_CBC:
            case EncryptionAlgorithm.DES40_CBC:
            case EncryptionAlgorithm.IDEA_CBC:
            case EncryptionAlgorithm.KUZNYECHIK_CTR_OMAC:
            case EncryptionAlgorithm.MAGMA_CTR_OMAC:
            case EncryptionAlgorithm.RC2_CBC_40:
            case EncryptionAlgorithm.RC4_128:
            case EncryptionAlgorithm.RC4_40:
            default:
                return false;
            }
        }

        /// <inheritdoc/>
        public override bool HasHkdfAlgorithm(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.sha256:
            case CryptoHashAlgorithm.sha384:
            case CryptoHashAlgorithm.sha512:
            case CryptoHashAlgorithm.sm3:
                return true;

            default:
                return false;
            }
        }

        /// <inheritdoc/>
        public override bool HasKemAgreement()
        {
            return true;
        }

        /// <inheritdoc/>
        public override bool HasMacAlgorithm(int macAlgorithm)
        {
            switch (macAlgorithm)
            {
            case MacAlgorithm.hmac_md5:
            case MacAlgorithm.hmac_sha1:
            case MacAlgorithm.hmac_sha256:
            case MacAlgorithm.hmac_sha384:
            case MacAlgorithm.hmac_sha512:
                return true;

            default:
                return false;
            }
        }

        /// <inheritdoc/>
        public override bool HasNamedGroup(int namedGroup)
        {
            return NamedGroup.RefersToASpecificCurve(namedGroup)
                || NamedGroup.RefersToASpecificFiniteField(namedGroup)
                || NamedGroup.RefersToASpecificKem(namedGroup);
        }

        /// <inheritdoc/>
        public override bool HasRsaEncryption()
        {
            return true;
        }

        /// <inheritdoc/>
        public override bool HasSignatureAlgorithm(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.dsa:
            case SignatureAlgorithm.ecdsa:
            case SignatureAlgorithm.ed25519:
            case SignatureAlgorithm.ed448:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
            case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
                return true;

            // TODO[RFC 9189]
            case SignatureAlgorithm.gostr34102012_256:
            case SignatureAlgorithm.gostr34102012_512:

            default:
                return false;
            }
        }

        /// <inheritdoc/>
        public override bool HasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
        {
            int signatureScheme = SignatureScheme.From(sigAndHashAlgorithm);
            if (SignatureScheme.IsMLDsaScheme(signatureScheme) ||
                SignatureScheme.IsSlhDsa(signatureScheme))
            {
                return HasSignatureScheme(signatureScheme);
            }

            short signature = sigAndHashAlgorithm.Signature;

            switch (sigAndHashAlgorithm.Hash)
            {
            case HashAlgorithm.md5:
                return SignatureAlgorithm.rsa == signature && HasSignatureAlgorithm(signature);
            default:
                return HasSignatureAlgorithm(signature);
            }
        }

        /// <inheritdoc/>
        public override bool HasSignatureScheme(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case SignatureScheme.mldsa44:
            case SignatureScheme.mldsa65:
            case SignatureScheme.mldsa87:
            case SignatureScheme.slhdsa_sha2_128s:
            case SignatureScheme.slhdsa_sha2_128f:
            case SignatureScheme.slhdsa_sha2_192s:
            case SignatureScheme.slhdsa_sha2_192f:
            case SignatureScheme.slhdsa_sha2_256s:
            case SignatureScheme.slhdsa_sha2_256f:
            case SignatureScheme.slhdsa_shake_128s:
            case SignatureScheme.slhdsa_shake_128f:
            case SignatureScheme.slhdsa_shake_192s:
            case SignatureScheme.slhdsa_shake_192f:
            case SignatureScheme.slhdsa_shake_256s:
            case SignatureScheme.slhdsa_shake_256f:
            case SignatureScheme.sm2sig_sm3:
                return true;
            default:
            {
                short signature = SignatureScheme.GetSignatureAlgorithm(signatureScheme);

                switch (SignatureScheme.GetCryptoHashAlgorithm(signatureScheme))
                {
                case CryptoHashAlgorithm.md5:
                    return SignatureAlgorithm.rsa == signature && HasSignatureAlgorithm(signature);
                default:
                    return HasSignatureAlgorithm(signature);
                }
            }
            }
        }

        /// <inheritdoc/>
        public override bool HasSrpAuthentication()
        {
            return true;
        }

        /// <inheritdoc/>
        public override TlsSecret CreateHybridSecret(TlsSecret s1, TlsSecret s2)
        {
            return AdoptLocalSecret(Arrays.Concatenate(s1.Extract(), s2.Extract()));
        }

        /// <inheritdoc/>
        public override TlsSecret CreateSecret(byte[] data)
        {
            try
            {
                return AdoptLocalSecret(Arrays.Clone(data));
            }
            finally
            {
                // TODO[tls-ops] Add this after checking all callers
                //if (data != null)
                //{
                //    Array.Clear(data, 0, data.Length);
                //}
            }
        }

        /// <inheritdoc/>
        public override TlsSecret GenerateRsaPreMasterSecret(ProtocolVersion version)
        {
            byte[] data = new byte[48];
            SecureRandom.NextBytes(data);
            TlsUtilities.WriteVersion(version, data, 0);
            return AdoptLocalSecret(data);
        }

        /// <summary>Create a copy of a digest with its current state.</summary>
        /// <param name="cryptoHashAlgorithm">The crypto hash algorithm.</param>
        /// <param name="digest">The digest to copy.</param>
        /// <returns>The copy.</returns>
        public virtual IDigest CloneDigest(int cryptoHashAlgorithm, IDigest digest)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.md5:
                return new MD5Digest((MD5Digest)digest);
            case CryptoHashAlgorithm.sha1:
                return new Sha1Digest((Sha1Digest)digest);
            case CryptoHashAlgorithm.sha224:
                return new Sha224Digest((Sha224Digest)digest);
            case CryptoHashAlgorithm.sha256:
                return new Sha256Digest((Sha256Digest)digest);
            case CryptoHashAlgorithm.sha384:
                return new Sha384Digest((Sha384Digest)digest);
            case CryptoHashAlgorithm.sha512:
                return new Sha512Digest((Sha512Digest)digest);
            case CryptoHashAlgorithm.sm3:
                return new SM3Digest((SM3Digest)digest);
            case CryptoHashAlgorithm.gostr3411_2012_256:
                return new Gost3411_2012_256Digest((Gost3411_2012_256Digest)digest);
            default:
                throw new ArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
            }
        }

        /// <summary>Create a digest for a hash algorithm.</summary>
        /// <param name="cryptoHashAlgorithm">The crypto hash algorithm.</param>
        /// <returns>The digest.</returns>
        public virtual IDigest CreateDigest(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.md5:
                return new MD5Digest();
            case CryptoHashAlgorithm.sha1:
                return new Sha1Digest();
            case CryptoHashAlgorithm.sha224:
                return new Sha224Digest();
            case CryptoHashAlgorithm.sha256:
                return new Sha256Digest();
            case CryptoHashAlgorithm.sha384:
                return new Sha384Digest();
            case CryptoHashAlgorithm.sha512:
                return new Sha512Digest();
            case CryptoHashAlgorithm.sm3:
                return new SM3Digest();
            case CryptoHashAlgorithm.gostr3411_2012_256:
                return new Gost3411_2012_256Digest();
            default:
                throw new ArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
            }
        }

        /// <inheritdoc/>
        public override TlsHash CreateHash(int cryptoHashAlgorithm)
        {
            return new BcTlsHash(this, cryptoHashAlgorithm);
        }

        /// <summary>Create a block cipher engine for an encryption algorithm.</summary>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <returns>The engine.</returns>
        protected virtual IBlockCipher CreateBlockCipher(int encryptionAlgorithm)
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.cls_3DES_EDE_CBC:
                return CreateDesEdeEngine();
            case EncryptionAlgorithm.AES_128_CBC:
            case EncryptionAlgorithm.AES_256_CBC:
                return CreateAesEngine();
            case EncryptionAlgorithm.ARIA_128_CBC:
            case EncryptionAlgorithm.ARIA_256_CBC:
                return CreateAriaEngine();
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
                return CreateCamelliaEngine();
            case EncryptionAlgorithm.SEED_CBC:
                return CreateSeedEngine();
            case EncryptionAlgorithm.SM4_CBC:
                return CreateSM4Engine();
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /// <summary>Create a CBC block cipher around an engine, or for an encryption algorithm.</summary>
        /// <param name="blockCipher">The engine.</param>
        /// <returns>The CBC block cipher.</returns>
        protected virtual IBlockCipher CreateCbcBlockCipher(IBlockCipher blockCipher)
        {
            return new CbcBlockCipher(blockCipher);
        }

        /// <summary>Create a CBC block cipher around an engine, or for an encryption algorithm.</summary>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <returns>The CBC block cipher.</returns>
        protected virtual IBlockCipher CreateCbcBlockCipher(int encryptionAlgorithm)
        {
            return CreateCbcBlockCipher(CreateBlockCipher(encryptionAlgorithm));
        }

        /// <summary>Create a ChaCha20-Poly1305 cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsCipher CreateChaCha20Poly1305(TlsCryptoParameters cryptoParams)
        {
            BcChaCha20Poly1305 encrypt = new BcChaCha20Poly1305(true);
            BcChaCha20Poly1305 decrypt = new BcChaCha20Poly1305(false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, 32, 16, TlsAeadCipher.AEAD_CHACHA20_POLY1305);
        }

        /// <summary>Create an AEAD cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="cipherKeySize">The size of the key in bytes.</param>
        /// <param name="macSize">The size of the MAC in bytes.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsAeadCipher CreateCipher_Aes_Ccm(TlsCryptoParameters cryptoParams, int cipherKeySize,
            int macSize)
        {
            var encrypt = new BcTlsCcmImpl(CreateAeadCipher_Aes_Ccm(), true);
            var decrypt = new BcTlsCcmImpl(CreateAeadCipher_Aes_Ccm(), false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAeadCipher.AEAD_CCM);
        }

        /// <summary>Create an AEAD cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="cipherKeySize">The size of the key in bytes.</param>
        /// <param name="macSize">The size of the MAC in bytes.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsAeadCipher CreateCipher_Aes_Gcm(TlsCryptoParameters cryptoParams, int cipherKeySize,
            int macSize)
        {
            BcTlsAeadCipherImpl encrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_Aes_Gcm(), true);
            BcTlsAeadCipherImpl decrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_Aes_Gcm(), false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAeadCipher.AEAD_GCM);
        }

        /// <summary>Create an AEAD cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="cipherKeySize">The size of the key in bytes.</param>
        /// <param name="macSize">The size of the MAC in bytes.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsAeadCipher CreateCipher_Aria_Gcm(TlsCryptoParameters cryptoParams, int cipherKeySize,
            int macSize)
        {
            BcTlsAeadCipherImpl encrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_Aria_Gcm(), true);
            BcTlsAeadCipherImpl decrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_Aria_Gcm(), false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAeadCipher.AEAD_GCM);
        }

        /// <summary>Create an AEAD cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="cipherKeySize">The size of the key in bytes.</param>
        /// <param name="macSize">The size of the MAC in bytes.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsAeadCipher CreateCipher_Camellia_Gcm(TlsCryptoParameters cryptoParams, int cipherKeySize,
            int macSize)
        {
            BcTlsAeadCipherImpl encrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_Camellia_Gcm(), true);
            BcTlsAeadCipherImpl decrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_Camellia_Gcm(), false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, TlsAeadCipher.AEAD_GCM);
        }

        /// <summary>Create a CBC cipher with a MAC.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <param name="cipherKeySize">The size of the key in bytes.</param>
        /// <param name="macAlgorithm">The MAC algorithm.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsCipher CreateCipher_Cbc(TlsCryptoParameters cryptoParams, int encryptionAlgorithm,
            int cipherKeySize, int macAlgorithm)
        {
            BcTlsBlockCipherImpl encrypt = new BcTlsBlockCipherImpl(CreateCbcBlockCipher(encryptionAlgorithm), true);
            BcTlsBlockCipherImpl decrypt = new BcTlsBlockCipherImpl(CreateCbcBlockCipher(encryptionAlgorithm), false);

            TlsHmac clientMac = CreateMac(cryptoParams, macAlgorithm);
            TlsHmac serverMac = CreateMac(cryptoParams, macAlgorithm);

            return new TlsBlockCipher(cryptoParams, encrypt, decrypt, clientMac, serverMac, cipherKeySize);
        }

        /// <summary>Create an SM4 AEAD cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsAeadCipher CreateCipher_SM4_Ccm(TlsCryptoParameters cryptoParams)
        {
            var encrypt = new BcTlsCcmImpl(CreateAeadCipher_SM4_Ccm(), true);
            var decrypt = new BcTlsCcmImpl(CreateAeadCipher_SM4_Ccm(), false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, 16, 16, TlsAeadCipher.AEAD_CCM);
        }

        /// <summary>Create an SM4 AEAD cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsAeadCipher CreateCipher_SM4_Gcm(TlsCryptoParameters cryptoParams)
        {
            BcTlsAeadCipherImpl encrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_SM4_Gcm(), true);
            BcTlsAeadCipherImpl decrypt = new BcTlsAeadCipherImpl(CreateAeadCipher_SM4_Gcm(), false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, 16, 16, TlsAeadCipher.AEAD_GCM);
        }

        /// <summary>Create a TLS 1.3 null cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="macAlgorithm">The MAC algorithm.</param>
        /// <returns>The cipher.</returns>
        protected virtual Tls13NullCipher Create13NullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm) =>
            new Tls13NullCipher(cryptoParams, CreateHmac(macAlgorithm), CreateHmac(macAlgorithm));

        /// <summary>Create a null cipher.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="macAlgorithm">The MAC algorithm.</param>
        /// <returns>The cipher.</returns>
        protected virtual TlsNullCipher CreateNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        {
            return new TlsNullCipher(cryptoParams, CreateMac(cryptoParams, macAlgorithm),
                CreateMac(cryptoParams, macAlgorithm));
        }

        /// <summary>Create an AES engine.</summary>
        /// <returns>The engine.</returns>
        protected virtual IBlockCipher CreateAesEngine()
        {
            return AesUtilities.CreateEngine();
        }

        /// <summary>Create an ARIA engine.</summary>
        /// <returns>The engine.</returns>
        protected virtual IBlockCipher CreateAriaEngine()
        {
            return new AriaEngine();
        }

        /// <summary>Create a Camellia engine.</summary>
        /// <returns>The engine.</returns>
        protected virtual IBlockCipher CreateCamelliaEngine()
        {
            return new CamelliaEngine();
        }

        /// <summary>Create a Triple DES (DESede) engine.</summary>
        /// <returns>The engine.</returns>
        protected virtual IBlockCipher CreateDesEdeEngine()
        {
            return new DesEdeEngine();
        }

        /// <summary>Create a SEED engine.</summary>
        /// <returns>The engine.</returns>
        protected virtual IBlockCipher CreateSeedEngine()
        {
            return new SeedEngine();
        }

        /// <summary>Create an SM4 engine.</summary>
        /// <returns>The engine.</returns>
        protected virtual IBlockCipher CreateSM4Engine()
        {
            return new SM4Engine();
        }

        /// <summary>Create a CCM mode cipher around an engine.</summary>
        /// <param name="engine">The engine.</param>
        /// <returns>The cipher.</returns>
        protected virtual CcmBlockCipher CreateCcmMode(IBlockCipher engine)
        {
            return new CcmBlockCipher(engine);
        }

        /// <summary>Create a GCM mode cipher around an engine.</summary>
        /// <param name="engine">The engine.</param>
        /// <returns>The cipher.</returns>
        protected virtual IAeadCipher CreateGcmMode(IBlockCipher engine)
        {
            return new GcmBlockCipher(engine);
        }

        /// <summary>Create an AES-CCM AEAD cipher.</summary>
        /// <returns>The cipher.</returns>
        protected virtual CcmBlockCipher CreateAeadCipher_Aes_Ccm()
        {
            return CreateCcmMode(CreateAesEngine());
        }

        /// <summary>Create an AES-GCM AEAD cipher.</summary>
        /// <returns>The cipher.</returns>
        protected virtual IAeadCipher CreateAeadCipher_Aes_Gcm()
        {
            return CreateGcmMode(CreateAesEngine());
        }

        /// <summary>Create an ARIA-GCM AEAD cipher.</summary>
        /// <returns>The cipher.</returns>
        protected virtual IAeadCipher CreateAeadCipher_Aria_Gcm()
        {
            return CreateGcmMode(CreateAriaEngine());
        }

        /// <summary>Create a Camellia-GCM AEAD cipher.</summary>
        /// <returns>The cipher.</returns>
        protected virtual IAeadCipher CreateAeadCipher_Camellia_Gcm()
        {
            return CreateGcmMode(CreateCamelliaEngine());
        }

        /// <summary>Create an SM4-CCM AEAD cipher.</summary>
        /// <returns>The cipher.</returns>
        protected virtual CcmBlockCipher CreateAeadCipher_SM4_Ccm()
        {
            return CreateCcmMode(CreateSM4Engine());
        }

        /// <summary>Create an SM4-GCM AEAD cipher.</summary>
        /// <returns>The cipher.</returns>
        protected virtual IAeadCipher CreateAeadCipher_SM4_Gcm()
        {
            return CreateGcmMode(CreateSM4Engine());
        }

        /// <inheritdoc/>
        public override TlsHmac CreateHmac(int macAlgorithm)
        {
            switch (macAlgorithm)
            {
            case MacAlgorithm.hmac_md5:
            case MacAlgorithm.hmac_sha1:
            case MacAlgorithm.hmac_sha256:
            case MacAlgorithm.hmac_sha384:
            case MacAlgorithm.hmac_sha512:
                return CreateHmacForHash(TlsCryptoUtilities.GetHashForHmac(macAlgorithm));

            default:
                throw new ArgumentException("invalid MacAlgorithm: " + macAlgorithm);
            }
        }

        /// <inheritdoc/>
        public override TlsHmac CreateHmacForHash(int cryptoHashAlgorithm)
        {
            return new BcTlsHmac(new HMac(CreateDigest(cryptoHashAlgorithm)));
        }

        /// <summary>Create an HMAC for the SSL 3.0 MAC construction.</summary>
        /// <param name="macAlgorithm">The MAC algorithm.</param>
        /// <returns>The HMAC.</returns>
        protected virtual TlsHmac CreateHmac_Ssl(int macAlgorithm)
        {
            switch (macAlgorithm)
            {
            case MacAlgorithm.hmac_md5:
                return new BcSsl3Hmac(CreateDigest(CryptoHashAlgorithm.md5));
            case MacAlgorithm.hmac_sha1:
                return new BcSsl3Hmac(CreateDigest(CryptoHashAlgorithm.sha1));
            case MacAlgorithm.hmac_sha256:
                return new BcSsl3Hmac(CreateDigest(CryptoHashAlgorithm.sha256));
            case MacAlgorithm.hmac_sha384:
                return new BcSsl3Hmac(CreateDigest(CryptoHashAlgorithm.sha384));
            case MacAlgorithm.hmac_sha512:
                return new BcSsl3Hmac(CreateDigest(CryptoHashAlgorithm.sha512));
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /// <summary>Create the HMAC for a MAC algorithm.</summary>
        /// <param name="cryptoParams">The crypto parameters.</param>
        /// <param name="macAlgorithm">The MAC algorithm.</param>
        /// <returns>The HMAC.</returns>
        protected virtual TlsHmac CreateMac(TlsCryptoParameters cryptoParams, int macAlgorithm)
        {
            if (TlsImplUtilities.IsSsl(cryptoParams))
            {
                return CreateHmac_Ssl(macAlgorithm);
            }
            else
            {
                return CreateHmac(macAlgorithm);
            }
        }

        /// <inheritdoc/>
        public override TlsSrp6Client CreateSrp6Client(TlsSrpConfig srpConfig)
        {
            BigInteger[] ng = srpConfig.GetExplicitNG();
            Srp6GroupParameters srpGroup = new Srp6GroupParameters(ng[0], ng[1]);

            Srp6Client srp6Client = new Srp6Client();
            srp6Client.Init(srpGroup, CreateDigest(CryptoHashAlgorithm.sha1), SecureRandom);

            return new BcTlsSrp6Client(srp6Client);
        }

        /// <inheritdoc/>
        public override TlsSrp6Server CreateSrp6Server(TlsSrpConfig srpConfig, BigInteger srpVerifier)
        {
            BigInteger[] ng = srpConfig.GetExplicitNG();
            Srp6GroupParameters srpGroup = new Srp6GroupParameters(ng[0], ng[1]);

            Srp6Server srp6Server = new Srp6Server();
            srp6Server.Init(srpGroup, srpVerifier, CreateDigest(CryptoHashAlgorithm.sha1), SecureRandom);

            return new BcTlsSrp6Server(srp6Server);
        }

        /// <inheritdoc/>
        public override TlsSrp6VerifierGenerator CreateSrp6VerifierGenerator(TlsSrpConfig srpConfig)
        {
            BigInteger[] ng = srpConfig.GetExplicitNG();

            Srp6VerifierGenerator srp6VerifierGenerator = new Srp6VerifierGenerator();
            srp6VerifierGenerator.Init(ng[0], ng[1], CreateDigest(CryptoHashAlgorithm.sha1));

            return new BcTlsSrp6VerifierGenerator(srp6VerifierGenerator);
        }

        /// <inheritdoc/>
        public override TlsSecret HkdfInit(int cryptoHashAlgorithm)
        {
            return AdoptLocalSecret(new byte[TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm)]);
        }
    }
}
