using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
    /// <summary>(D)TLS DH key exchange.</summary>
    public class TlsDHKeyExchange
        :   AbstractTlsKeyExchange
    {
        protected TlsSigner mTlsSigner;
        protected DHParameters mDHParameters;

        protected AsymmetricKeyParameter mServerPublicKey;
        protected DHPublicKeyParameters mDHAgreeServerPublicKey;
        protected TlsAgreementCredentials mAgreementCredentials;
        protected DHPrivateKeyParameters mDHAgreeClientPrivateKey;

        protected DHPrivateKeyParameters mDHAgreeServerPrivateKey;
        protected DHPublicKeyParameters mDHAgreeClientPublicKey;

        public TlsDHKeyExchange(int keyExchange, IList supportedSignatureAlgorithms, DHParameters dhParameters)
            :   base(keyExchange, supportedSignatureAlgorithms)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.DH_RSA:
            case KeyExchangeAlgorithm.DH_DSS:
                this.mTlsSigner = null;
                break;
            case KeyExchangeAlgorithm.DHE_RSA:
                this.mTlsSigner = new TlsRsaSigner();
                break;
            case KeyExchangeAlgorithm.DHE_DSS:
                this.mTlsSigner = new TlsDssSigner();
                break;
            default:
                throw new InvalidOperationException("unsupported key exchange algorithm");
            }

            this.mDHParameters = dhParameters;
        }

        public override void Init(TlsContext context)
        {
            base.Init(context);

            if (this.mTlsSigner != null)
            {
                this.mTlsSigner.Init(context);
            }
        }

        public override void SkipServerCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            if (serverCertificate.IsEmpty)
                throw new TlsFatalAlert(AlertDescription.bad_certificate);

            X509CertificateStructure x509Cert = serverCertificate.GetCertificateAt(0);

            SubjectPublicKeyInfo keyInfo = x509Cert.SubjectPublicKeyInfo;
            try
            {
                this.mServerPublicKey = PublicKeyFactory.CreateKey(keyInfo);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
            }

            if (mTlsSigner == null)
            {
                try
                {
                    this.mDHAgreeServerPublicKey = TlsDHUtilities.ValidateDHPublicKey((DHPublicKeyParameters)this.mServerPublicKey);
                }
                catch (InvalidCastException e)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
                }

                TlsUtilities.ValidateKeyUsage(x509Cert, KeyUsage.KeyAgreement);
            }
            else
            {
                if (!mTlsSigner.IsValidPublicKey(this.mServerPublicKey))
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }

                TlsUtilities.ValidateKeyUsage(x509Cert, KeyUsage.DigitalSignature);
            }

            base.ProcessServerCertificate(serverCertificate);
        }

        public override bool RequiresServerKeyExchange
        {
            get
            {
                switch (mKeyExchange)
                {
                case KeyExchangeAlgorithm.DHE_DSS:
                case KeyExchangeAlgorithm.DHE_RSA:
                case KeyExchangeAlgorithm.DH_anon:
                    return true;
                default:
                    return false;
                }
            }
        }

        public override void ValidateCertificateRequest(CertificateRequest certificateRequest)
        {
            byte[] types = certificateRequest.CertificateTypes;
            for (int i = 0; i < types.Length; ++i)
            {
                switch (types[i])
                {
                case ClientCertificateType.rsa_sign:
                case ClientCertificateType.dss_sign:
                case ClientCertificateType.rsa_fixed_dh:
                case ClientCertificateType.dss_fixed_dh:
                case ClientCertificateType.ecdsa_sign:
                    break;
                default:
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        public override void ProcessClientCredentials(TlsCredentials clientCredentials)
        {
            if (clientCredentials is TlsAgreementCredentials)
            {
                // TODO Validate client cert has matching parameters (see 'areCompatibleParameters')?

                this.mAgreementCredentials = (TlsAgreementCredentials)clientCredentials;
            }
            else if (clientCredentials is TlsSignerCredentials)
            {
                // OK
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public override void GenerateClientKeyExchange(Stream output)
        {
            /*
             * RFC 2246 7.4.7.2 If the client certificate already contains a suitable Diffie-Hellman
             * key, then Yc is implicit and does not need to be sent again. In this case, the Client Key
             * Exchange message will be sent, but will be empty.
             */
            if (mAgreementCredentials == null)
            {
                this.mDHAgreeClientPrivateKey = TlsDHUtilities.GenerateEphemeralClientKeyExchange(context.SecureRandom,
                    mDHAgreeServerPublicKey.Parameters, output);
            }
        }

        public override byte[] GeneratePremasterSecret()
        {
            if (mAgreementCredentials != null)
            {
                return mAgreementCredentials.GenerateAgreement(mDHAgreeServerPublicKey);
            }

            if (mDHAgreeServerPrivateKey != null)
            {
                return TlsDHUtilities.CalculateDHBasicAgreement(mDHAgreeClientPublicKey, mDHAgreeServerPrivateKey);
            }

            if (mDHAgreeClientPrivateKey != null)
            {
                return TlsDHUtilities.CalculateDHBasicAgreement(mDHAgreeServerPublicKey, mDHAgreeClientPrivateKey);
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
