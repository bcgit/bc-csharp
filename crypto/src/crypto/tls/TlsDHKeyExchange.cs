using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using System.Collections.Generic;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{
	/// <summary>
 /// TLS 1.0/1.1 DH key exchange.
	/// </summary>
    internal class TlsDHKeyExchange : AbstractTlsKeyExchange
    {
        protected static readonly BigInteger ONE = BigInteger.ValueOf(1);
        protected static readonly BigInteger TWO = BigInteger.ValueOf(2);

        protected TlsSigner tlsSigner;
        protected DHParameters dhParameters;

        protected AsymmetricKeyParameter serverPublicKey;
        protected DHPublicKeyParameters dhAgreeServerPublicKey;
        protected TlsAgreementCredentials agreementCredentials;
        protected DHPrivateKeyParameters dhAgreeClientPrivateKey;

        protected DHPrivateKeyParameters dhAgreeServerPrivateKey;
        protected DHPublicKeyParameters dhAgreeClientPublicKey;

        public TlsDHKeyExchange(KeyExchangeAlgorithm keyExchange, IList supportedSignatureAlgorithms, DHParameters dhParameters)            
            : base(keyExchange, supportedSignatureAlgorithms)
        {
            switch (keyExchange)
            {
                case KeyExchangeAlgorithm.DH_RSA:
                case KeyExchangeAlgorithm.DH_DSS:
                    this.tlsSigner = null;
                    break;
                case KeyExchangeAlgorithm.DHE_RSA:
                    this.tlsSigner = new TlsRsaSigner();
                    break;
                case KeyExchangeAlgorithm.DHE_DSS:
                    this.tlsSigner = new TlsDssSigner();
                    break;
                default:
                    throw new ArgumentException("unsupported key exchange algorithm");
            }

            this.dhParameters = dhParameters;
        }

        public override void Init(TlsContext context)
        {
            base.Init(context);

            if (this.tlsSigner != null)
            {
                this.tlsSigner.Init(context);
            }
        }

        public override void SkipServerCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            if (serverCertificate.IsEmpty)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }

            var x509Cert = serverCertificate.GetCertificateAt(0);

            SubjectPublicKeyInfo keyInfo = x509Cert.SubjectPublicKeyInfo;
            try
            {
                this.serverPublicKey = PublicKeyFactory.CreateKey(keyInfo);
            }
            catch (Exception)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
            }

            if (tlsSigner == null)
            {
                try
                {
                    this.dhAgreeServerPublicKey = TlsDHUtilities.ValidateDHPublicKey((DHPublicKeyParameters)this.serverPublicKey);
                }
                catch (InvalidCastException)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }

                TlsUtilities.ValidateKeyUsage(x509Cert, KeyUsage.KeyAgreement);
            }
            else
            {
                if (!tlsSigner.IsValidPublicKey(this.serverPublicKey))
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }

                TlsUtilities.ValidateKeyUsage(x509Cert, KeyUsage.DigitalSignature);
            }

            base.ProcessServerCertificate(serverCertificate);
            /*
            * Perform various checks per RFC2246 7.4.2: "Unless otherwise specified, the
            * signing algorithm for the certificate must be the same as the algorithm for the
            * certificate key."
            */
        }

        public override bool RequiresServerKeyExchange
        {
            get
            {
                switch (keyExchange)
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
            ClientCertificateType[] types = certificateRequest.CertificateTypes;
            foreach (ClientCertificateType type in types)
            {
                switch (type)
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

                this.agreementCredentials = (TlsAgreementCredentials)clientCredentials;
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
             * RFC 2246 7.4.7.2 If the client certificate already contains a suitable
             * Diffie-Hellman key, then Yc is implicit and does not need to be sent again. In
             * this case, the Client Key Exchange message will be sent, but will be empty.
             */
            if (agreementCredentials == null)
            {
                this.dhAgreeClientPrivateKey = TlsDHUtilities.GenerateEphemeralClientKeyExchange(context.SecureRandom,
                    dhAgreeServerPublicKey.Parameters, output);
            }
        }

        public override byte[] GeneratePremasterSecret()
        {
            if (agreementCredentials != null)
            {
                return agreementCredentials.GenerateAgreement(dhAgreeServerPublicKey);
            }

            if (dhAgreeServerPrivateKey != null)
            {
                return TlsDHUtilities.CalculateDHBasicAgreement(dhAgreeClientPublicKey, dhAgreeServerPrivateKey);
            }

            if (dhAgreeClientPrivateKey != null)
            {
                return TlsDHUtilities.CalculateDHBasicAgreement(dhAgreeServerPublicKey, dhAgreeClientPrivateKey);
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
