using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for a single X.509 certificate based on the BC light-weight API.</summary>
    public class BcTlsCertificate
        : TlsCertificate
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
                return X509CertificateStructure.GetInstance(encoding);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
            }
        }

        protected readonly BcTlsCrypto m_crypto;
        protected readonly X509CertificateStructure m_certificate;

        protected DHPublicKeyParameters m_pubKeyDH = null;
        protected ECPublicKeyParameters m_pubKeyEC = null;
        protected Ed25519PublicKeyParameters m_pubKeyEd25519 = null;
        protected Ed448PublicKeyParameters m_pubKeyEd448 = null;
        protected RsaKeyParameters m_pubKeyRsa = null;

        /// <exception cref="IOException"/>
        public BcTlsCertificate(BcTlsCrypto crypto, byte[] encoding)
            : this(crypto, ParseCertificate(encoding))
        {
        }

        public BcTlsCertificate(BcTlsCrypto crypto, X509CertificateStructure certificate)
        {
            this.m_crypto = crypto;
            this.m_certificate = certificate;
        }

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

            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        public virtual TlsVerifier CreateVerifier(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
            case SignatureAlgorithm.ed25519:
            case SignatureAlgorithm.ed448:
            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return CreateVerifier(SignatureScheme.From(HashAlgorithm.Intrinsic, signatureAlgorithm));
            }

            ValidateKeyUsage(KeyUsage.DigitalSignature);

            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
                ValidateRsa_Pkcs1();
                return new BcTlsRsaVerifier(m_crypto, GetPubKeyRsa());

            case SignatureAlgorithm.dsa:
                return new BcTlsDsaVerifier(m_crypto, GetPubKeyDss());

            case SignatureAlgorithm.ecdsa:
                return new BcTlsECDsaVerifier(m_crypto, GetPubKeyEC());

            default:
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }
        }

        /// <exception cref="IOException"/>
        public virtual TlsVerifier CreateVerifier(int signatureScheme)
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
                return new BcTlsECDsa13Verifier(m_crypto, GetPubKeyEC(), signatureScheme);

            case SignatureScheme.ed25519:
                return new BcTlsEd25519Verifier(m_crypto, GetPubKeyEd25519());

            case SignatureScheme.ed448:
                return new BcTlsEd448Verifier(m_crypto, GetPubKeyEd448());

            case SignatureScheme.rsa_pkcs1_sha1:
            case SignatureScheme.rsa_pkcs1_sha256:
            case SignatureScheme.rsa_pkcs1_sha384:
            case SignatureScheme.rsa_pkcs1_sha512:
            {
                ValidateRsa_Pkcs1();
                return new BcTlsRsaVerifier(m_crypto, GetPubKeyRsa());
            }

            case SignatureScheme.rsa_pss_pss_sha256:
            case SignatureScheme.rsa_pss_pss_sha384:
            case SignatureScheme.rsa_pss_pss_sha512:
            {
                ValidateRsa_Pss_Pss(SignatureScheme.GetSignatureAlgorithm(signatureScheme));
                return new BcTlsRsaPssVerifier(m_crypto, GetPubKeyRsa(), signatureScheme);
            }

            case SignatureScheme.rsa_pss_rsae_sha256:
            case SignatureScheme.rsa_pss_rsae_sha384:
            case SignatureScheme.rsa_pss_rsae_sha512:
            {
                ValidateRsa_Pss_Rsae();
                return new BcTlsRsaPssVerifier(m_crypto, GetPubKeyRsa(), signatureScheme);
            }

            // TODO[RFC 8998]
            //case SignatureScheme.sm2sig_sm3:
            //    return new BcTlsSM2Verifier(m_crypto, GetPubKeyEC(), Strings.ToByteArray("TLSv1.3+GM+Cipher+Suite"));

            default:
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }
        }

        /// <exception cref="IOException"/>
        public virtual byte[] GetEncoded()
        {
            return m_certificate.GetEncoded(Asn1Encodable.Der);
        }

        /// <exception cref="IOException"/>
        public virtual byte[] GetExtension(DerObjectIdentifier extensionOid)
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

        public virtual BigInteger SerialNumber
        {
            get { return m_certificate.SerialNumber.Value; }
        }

        public virtual string SigAlgOid
        {
            get { return m_certificate.SignatureAlgorithm.Algorithm.Id; }
        }

        public virtual Asn1Encodable GetSigAlgParams()
        {
            return m_certificate.SignatureAlgorithm.Parameters;
        }

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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
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

            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual AsymmetricKeyParameter GetPublicKey()
        {
            SubjectPublicKeyInfo keyInfo = m_certificate.SubjectPublicKeyInfo;
            try
            {
                return PublicKeyFactory.CreateKey(keyInfo);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
            }
        }

        protected virtual bool SupportsKeyUsage(int keyUsageBits)
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

        protected virtual bool SupportsRsa_Pkcs1()
        {
            AlgorithmIdentifier pubKeyAlgID = m_certificate.SubjectPublicKeyInfo.AlgorithmID;
            return RsaUtilities.SupportsPkcs1(pubKeyAlgID);
        }

        protected virtual bool SupportsRsa_Pss_Pss(short signatureAlgorithm)
        {
            AlgorithmIdentifier pubKeyAlgID = m_certificate.SubjectPublicKeyInfo.AlgorithmID;
            return RsaUtilities.SupportsPss_Pss(signatureAlgorithm, pubKeyAlgID);
        }

        protected virtual bool SupportsRsa_Pss_Rsae()
        {
            AlgorithmIdentifier pubKeyAlgID = m_certificate.SubjectPublicKeyInfo.AlgorithmID;
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

            default:
                return false;
            }
        }

        /// <exception cref="IOException"/>
        public virtual void ValidateKeyUsage(int keyUsageBits)
        {
            if (!SupportsKeyUsage(keyUsageBits))
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pkcs1()
        {
            if (!SupportsRsa_Pkcs1())
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pss_Pss(short signatureAlgorithm)
        {
            if (!SupportsRsa_Pss_Pss(signatureAlgorithm))
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pss_Rsae()
        {
            if (!SupportsRsa_Pss_Rsae())
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }
    }
}
