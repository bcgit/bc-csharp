using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for a single X.509 certificate based on the BC light-weight API.</summary>
    public class BcTlsRawKeyCertificate
        : TlsCertificate
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly SubjectPublicKeyInfo m_keyInfo;

        protected DHPublicKeyParameters m_pubKeyDH = null;
        protected ECPublicKeyParameters m_pubKeyEC = null;
        protected Ed25519PublicKeyParameters m_pubKeyEd25519 = null;
        protected Ed448PublicKeyParameters m_pubKeyEd448 = null;
        protected RsaKeyParameters m_pubKeyRsa = null;

        /// <exception cref="IOException"/>
        public BcTlsRawKeyCertificate(BcTlsCrypto crypto, byte[] encoding)
            : this(crypto, SubjectPublicKeyInfo.GetInstance(encoding))
        {
        }

        public BcTlsRawKeyCertificate(BcTlsCrypto crypto, SubjectPublicKeyInfo keyInfo)
        {
            m_crypto = crypto;
            m_keyInfo = keyInfo;
        }

        public virtual SubjectPublicKeyInfo SubjectPublicKeyInfo => m_keyInfo;

        /// <exception cref="IOException"/>
        public virtual TlsEncryptor CreateEncryptor(int tlsCertificateRole)
        {
            ValidateKeyUsage(KeyUsage.KeyEncipherment);

            switch (tlsCertificateRole)
            {
            case TlsCertificateRole.RsaEncryption:
            {
                this.m_pubKeyRsa = GetPubKeyRsa();
                return new BcTlsRsaEncryptor(m_crypto, m_pubKeyRsa);
            }
            // TODO[gmssl]
            //case TlsCertificateRole.Sm2Encryption:
            //{
            //    this.m_pubKeyEC = GetPubKeyEC();
            //    return new BcTlsSM2Encryptor(m_crypto, m_pubKeyEC);
            //}
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <exception cref="IOException"/>
        public virtual TlsVerifier CreateVerifier(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.ed25519:
            case SignatureAlgorithm.ed448:
            {
                int signatureScheme = SignatureScheme.From(HashAlgorithm.Intrinsic, signatureAlgorithm);
                Tls13Verifier tls13Verifier = CreateVerifier(signatureScheme);
                return new LegacyTls13Verifier(signatureScheme, tls13Verifier);
            }
            }

            ValidateKeyUsage(KeyUsage.DigitalSignature);

            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.dsa:
                return new BcTlsDsaVerifier(m_crypto, GetPubKeyDss());

            case SignatureAlgorithm.ecdsa:
                return new BcTlsECDsaVerifier(m_crypto, GetPubKeyEC());

            case SignatureAlgorithm.rsa:
            {
                ValidateRsa_Pkcs1();
                return new BcTlsRsaVerifier(m_crypto, GetPubKeyRsa());
            }

            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
            {
                ValidateRsa_Pss_Pss(signatureAlgorithm);
                int signatureScheme = SignatureScheme.From(HashAlgorithm.Intrinsic, signatureAlgorithm);
                return new BcTlsRsaPssVerifier(m_crypto, GetPubKeyRsa(), signatureScheme);
            }

            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
            {
                ValidateRsa_Pss_Rsae();
                int signatureScheme = SignatureScheme.From(HashAlgorithm.Intrinsic, signatureAlgorithm);
                return new BcTlsRsaPssVerifier(m_crypto, GetPubKeyRsa(), signatureScheme);
            }

            // TODO[RFC 9189]
            case SignatureAlgorithm.gostr34102012_256:
            case SignatureAlgorithm.gostr34102012_512:

            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /// <exception cref="IOException"/>
        public virtual Tls13Verifier CreateVerifier(int signatureScheme)
        {
            ValidateKeyUsage(KeyUsage.DigitalSignature);

            switch (signatureScheme)
            {
            case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512:
            case SignatureScheme.ecdsa_secp256r1_sha256:
            case SignatureScheme.ecdsa_secp384r1_sha384:
            case SignatureScheme.ecdsa_secp521r1_sha512:
            case SignatureScheme.ecdsa_sha1:
            {
                int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
                IDigest digest = m_crypto.CreateDigest(cryptoHashAlgorithm);

                ISigner verifier = new DsaDigestSigner(new ECDsaSigner(), digest);
                verifier.Init(false, GetPubKeyEC());

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.ed25519:
            {
                Ed25519Signer verifier = new Ed25519Signer();
                verifier.Init(false, GetPubKeyEd25519());

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.ed448:
            {
                Ed448Signer verifier = new Ed448Signer(TlsUtilities.EmptyBytes);
                verifier.Init(false, GetPubKeyEd448());

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.rsa_pkcs1_sha1:
            case SignatureScheme.rsa_pkcs1_sha256:
            case SignatureScheme.rsa_pkcs1_sha384:
            case SignatureScheme.rsa_pkcs1_sha512:
            {
                ValidateRsa_Pkcs1();

                int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
                IDigest digest = m_crypto.CreateDigest(cryptoHashAlgorithm);

                RsaDigestSigner verifier = new RsaDigestSigner(digest,
                    TlsCryptoUtilities.GetOidForHash(cryptoHashAlgorithm));
                verifier.Init(false, GetPubKeyRsa());

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.rsa_pss_pss_sha256:
            case SignatureScheme.rsa_pss_pss_sha384:
            case SignatureScheme.rsa_pss_pss_sha512:
            {
                ValidateRsa_Pss_Pss(SignatureScheme.GetSignatureAlgorithm(signatureScheme));

                int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
                IDigest digest = m_crypto.CreateDigest(cryptoHashAlgorithm);

                PssSigner verifier = new PssSigner(new RsaEngine(), digest, digest.GetDigestSize());
                verifier.Init(false, GetPubKeyRsa());

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.rsa_pss_rsae_sha256:
            case SignatureScheme.rsa_pss_rsae_sha384:
            case SignatureScheme.rsa_pss_rsae_sha512:
            {
                ValidateRsa_Pss_Rsae();

                int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
                IDigest digest = m_crypto.CreateDigest(cryptoHashAlgorithm);

                PssSigner verifier = new PssSigner(new RsaEngine(), digest, digest.GetDigestSize());
                verifier.Init(false, GetPubKeyRsa());

                return new BcTls13Verifier(verifier);
            }

            // TODO[RFC 8998]
            //case SignatureScheme.sm2sig_sm3:
            //{
            //    ParametersWithID parametersWithID = new ParametersWithID(GetPubKeyEC(),
            //        Strings.ToByteArray("TLSv1.3+GM+Cipher+Suite"));
    
            //    SM2Signer verifier = new SM2Signer();
            //    verifier.Init(false, parametersWithID);

            //    return new BcTls13Verifier(verifier);
            //}

            case SignatureScheme.mldsa44:
            case SignatureScheme.mldsa65:
            case SignatureScheme.mldsa87:
            {
                var mlDsaAlgOid = PqcUtilities.GetMLDsaObjectidentifier(signatureScheme);
                ValidateMLDsa(mlDsaAlgOid);

                var publicKey = GetPubKeyMLDsa();

                var verifier = SignerUtilities.InitSigner(mlDsaAlgOid, forSigning: false, publicKey, random: null);

                return new BcTls13Verifier(verifier);
            }

            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /// <exception cref="IOException"/>
        public virtual byte[] GetEncoded()
        {
            return m_keyInfo.GetEncoded(Asn1Encodable.Der);
        }

        /// <exception cref="IOException"/>
        public virtual byte[] GetExtension(DerObjectIdentifier extensionOid)
        {
            return null;
        }

        public virtual BigInteger SerialNumber => null;

        public virtual string SigAlgOid => null;

        public virtual Asn1Encodable GetSigAlgParams() => null;

        /// <exception cref="IOException"/>
        public virtual short GetLegacySignatureAlgorithm()
        {
            AsymmetricKeyParameter publicKey = GetPublicKey();
            if (publicKey.IsPrivate)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            if (!SupportsKeyUsage(KeyUsage.DigitalSignature))
                return -1;

            /*
             * RFC 5246 7.4.6. Client Certificate
             */

            /*
             * RSA public key; the certificate MUST allow the key to be used for signing with the
             * signature scheme and hash algorithm that will be employed in the certificate verify
             * message.
             */
            if (publicKey is RsaKeyParameters)
                return SignatureAlgorithm.rsa;

            /*
                * DSA public key; the certificate MUST allow the key to be used for signing with the
                * hash algorithm that will be employed in the certificate verify message.
                */
            if (publicKey is DsaPublicKeyParameters)
                return SignatureAlgorithm.dsa;

            /*
             * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
             * with the hash algorithm that will be employed in the certificate verify message; the
             * public key MUST use a curve and point format supported by the server.
             */
            if (publicKey is ECPublicKeyParameters)
            {
                // TODO Check the curve and point format
                return SignatureAlgorithm.ecdsa;
            }

            return -1;
        }

        /// <exception cref="IOException"/>
        public virtual DHPublicKeyParameters GetPubKeyDH()
        {
            try
            {
                return (DHPublicKeyParameters)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not DH", e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual DsaPublicKeyParameters GetPubKeyDss()
        {
            try
            {
                return (DsaPublicKeyParameters)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not DSS", e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual ECPublicKeyParameters GetPubKeyEC()
        {
            try
            {
                return (ECPublicKeyParameters)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not EC", e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual Ed25519PublicKeyParameters GetPubKeyEd25519()
        {
            try
            {
                return (Ed25519PublicKeyParameters)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not Ed25519", e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual Ed448PublicKeyParameters GetPubKeyEd448()
        {
            try
            {
                return (Ed448PublicKeyParameters)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not Ed448", e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual MLDsaPublicKeyParameters GetPubKeyMLDsa()
        {
            try
            {
                return (MLDsaPublicKeyParameters)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not ML-DSA", e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual RsaKeyParameters GetPubKeyRsa()
        {
            try
            {
                return (RsaKeyParameters)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Public key not RSA", e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual bool SupportsSignatureAlgorithm(short signatureAlgorithm)
        {
            return SupportsSignatureAlgorithm(signatureAlgorithm, KeyUsage.DigitalSignature);
        }

        /// <exception cref="IOException"/>
        public virtual bool SupportsSignatureAlgorithmCA(short signatureAlgorithm)
        {
            return SupportsSignatureAlgorithm(signatureAlgorithm, KeyUsage.KeyCertSign);
        }

        /// <exception cref="IOException"/>
        public virtual TlsCertificate CheckUsageInRole(int tlsCertificateRole)
        {
            switch (tlsCertificateRole)
            {
            case TlsCertificateRole.DH:
            {
                ValidateKeyUsage(KeyUsage.KeyAgreement);
                this.m_pubKeyDH = GetPubKeyDH();
                return this;
            }
            case TlsCertificateRole.ECDH:
            {
                ValidateKeyUsage(KeyUsage.KeyAgreement);
                this.m_pubKeyEC = GetPubKeyEC();
                return this;
            }
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <exception cref="IOException"/>
        protected virtual AsymmetricKeyParameter GetPublicKey()
        {
            try
            {
                return PublicKeyFactory.CreateKey(m_keyInfo);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
            }
        }

        // TODO[api] Rename parameter to 'keyUsageBit'
        protected virtual bool SupportsKeyUsage(int keyUsageBits)
        {
            return true;
        }

        protected virtual bool SupportsMLDsa(DerObjectIdentifier mlDsaAlgOid)
        {
            AlgorithmIdentifier pubKeyAlgID = m_keyInfo.Algorithm;
            return PqcUtilities.SupportsMLDsa(pubKeyAlgID, mlDsaAlgOid);
        }

        protected virtual bool SupportsRsa_Pkcs1()
        {
            AlgorithmIdentifier pubKeyAlgID = m_keyInfo.Algorithm;
            return RsaUtilities.SupportsPkcs1(pubKeyAlgID);
        }

        protected virtual bool SupportsRsa_Pss_Pss(short signatureAlgorithm)
        {
            AlgorithmIdentifier pubKeyAlgID = m_keyInfo.Algorithm;
            return RsaUtilities.SupportsPss_Pss(signatureAlgorithm, pubKeyAlgID);
        }

        protected virtual bool SupportsRsa_Pss_Rsae()
        {
            AlgorithmIdentifier pubKeyAlgID = m_keyInfo.Algorithm;
            return RsaUtilities.SupportsPss_Rsae(pubKeyAlgID);
        }

        /// <exception cref="IOException"/>
        protected virtual bool SupportsSignatureAlgorithm(short signatureAlgorithm, int keyUsage)
        {
            if (!SupportsKeyUsage(keyUsage))
                return false;

            AsymmetricKeyParameter publicKey = GetPublicKey();

            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
                return SupportsRsa_Pkcs1()
                    && publicKey is RsaKeyParameters;

            case SignatureAlgorithm.dsa:
                return publicKey is DsaPublicKeyParameters;

            case SignatureAlgorithm.ecdsa:
            case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
                return publicKey is ECPublicKeyParameters;

            case SignatureAlgorithm.ed25519:
                return publicKey is Ed25519PublicKeyParameters;

            case SignatureAlgorithm.ed448:
                return publicKey is Ed448PublicKeyParameters;

            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
                return SupportsRsa_Pss_Rsae()
                    && publicKey is RsaKeyParameters;

            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return SupportsRsa_Pss_Pss(signatureAlgorithm)
                    && publicKey is RsaKeyParameters;

            // TODO[RFC 9189]
            case SignatureAlgorithm.gostr34102012_256:
            case SignatureAlgorithm.gostr34102012_512:

            default:
                return false;
            }
        }

        /// <exception cref="IOException"/>
        // TODO[api] Rename parameter to 'keyUsageBit'
        public virtual void ValidateKeyUsage(int keyUsageBits)
        {
            if (!SupportsKeyUsage(keyUsageBits))
            {
                switch (keyUsageBits)
                {
                case KeyUsage.DigitalSignature:
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                        "KeyUsage does not allow digital signatures");
                case KeyUsage.KeyAgreement:
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                        "KeyUsage does not allow key agreement");
                case KeyUsage.KeyEncipherment:
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                        "KeyUsage does not allow key encipherment");
                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateMLDsa(DerObjectIdentifier mlDsaAlgOid)
        {
            if (!SupportsMLDsa(mlDsaAlgOid))
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "No support for ML-DSA signature scheme");
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pkcs1()
        {
            if (!SupportsRsa_Pkcs1())
                throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                    "No support for rsa_pkcs1 signature schemes");
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pss_Pss(short signatureAlgorithm)
        {
            if (!SupportsRsa_Pss_Pss(signatureAlgorithm))
                throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                    "No support for rsa_pss_pss signature schemes");
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pss_Rsae()
        {
            if (!SupportsRsa_Pss_Rsae())
                throw new TlsFatalAlert(AlertDescription.certificate_unknown,
                    "No support for rsa_pss_rsae signature schemes");
        }
    }
}
