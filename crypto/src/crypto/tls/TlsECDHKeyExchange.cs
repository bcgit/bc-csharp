using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    /**
    * ECDH key exchange (see RFC 4492)
    */
    internal class TlsECDHKeyExchange
        : AbstractTlsKeyExchange
    {
        protected TlsSigner tlsSigner;
        protected NamedCurve[] namedCurves;
        protected ECPointFormat[] clientECPointFormats, serverECPointFormats;

        protected AsymmetricKeyParameter serverPublicKey;
        protected TlsAgreementCredentials agreementCredentials;

        protected ECPrivateKeyParameters ecAgreePrivateKey;
        protected ECPublicKeyParameters ecAgreePublicKey;

        public TlsECDHKeyExchange(KeyExchangeAlgorithm keyExchange, IList supportedSignatureAlgorithms, NamedCurve[] namedCurves,
                                    ECPointFormat[] clientECPointFormats, ECPointFormat[] serverECPointFormats)
            : base(keyExchange, supportedSignatureAlgorithms)
        {
            switch (keyExchange)
            {
                case KeyExchangeAlgorithm.ECDHE_RSA:
                    this.tlsSigner = new TlsRsaSigner();
                    break;
                case KeyExchangeAlgorithm.ECDHE_ECDSA:
                    this.tlsSigner = new TlsECDsaSigner();
                    break;
                case KeyExchangeAlgorithm.ECDH_RSA:
                case KeyExchangeAlgorithm.ECDH_ECDSA:
                    this.tlsSigner = null;
                    break;
                default:
                    throw new ArgumentException("unsupported key exchange algorithm");
            }

            this.keyExchange = keyExchange;
            this.namedCurves = namedCurves;
            this.clientECPointFormats = clientECPointFormats;
            this.serverECPointFormats = serverECPointFormats;
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
                    this.ecAgreePublicKey = TlsECCUtils.ValidateECPublicKey((ECPublicKeyParameters)this.serverPublicKey);
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

            // TODO
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
                    case KeyExchangeAlgorithm.ECDHE_ECDSA:
                    case KeyExchangeAlgorithm.ECDHE_RSA:
                    case KeyExchangeAlgorithm.ECDH_anon:
                        return true;
                    default:
                        return false;
                }
            }
        }

        public override void ValidateCertificateRequest(CertificateRequest certificateRequest)
        {
            /*
             * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable
             * with ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is
             * prohibited because the use of a long-term ECDH client key would jeopardize the
             * forward secrecy property of these algorithms.
             */
            ClientCertificateType[] types = certificateRequest.CertificateTypes;
            foreach (ClientCertificateType type in types)
            {
                switch (type)
                {
                    case ClientCertificateType.rsa_sign:
                    case ClientCertificateType.dss_sign:
                    case ClientCertificateType.ecdsa_sign:
                    case ClientCertificateType.rsa_fixed_ecdh:
                    case ClientCertificateType.ecdsa_fixed_ecdh:
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
                // TODO Validate client cert has matching parameters (see 'AreOnSameCurve')?

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
            if (agreementCredentials == null)
            {
                this.ecAgreePrivateKey = TlsECCUtils.GenerateEphemeralClientKeyExchange(context.SecureRandom,
                    serverECPointFormats, ecAgreePublicKey.Parameters, output);
            }
        }

        public override void ProcessClientCertificate(Certificate clientCertificate)
        {
            // TODO Extract the public key
            // TODO If the certificate is 'fixed', take the public key as ecAgreeClientPublicKey
        }

        public override void ProcessClientKeyExchange(Stream input)
        {
            if (ecAgreePublicKey != null)
            {
                // For ecdsa_fixed_ecdh and rsa_fixed_ecdh, the key arrived in the client certificate
                return;
            }

            byte[] point = TlsUtilities.ReadOpaque8(input);

            ECDomainParameters curve_params = this.ecAgreePrivateKey.Parameters;

            this.ecAgreePublicKey = TlsECCUtils.ValidateECPublicKey(TlsECCUtils.DeserializeECPublicKey(
                serverECPointFormats, curve_params, point));
        }

        public override byte[] GeneratePremasterSecret()
        {
            if (agreementCredentials != null)
            {
                return agreementCredentials.GenerateAgreement(ecAgreePublicKey);
            }

            if (ecAgreePrivateKey != null)
            {
                return TlsECCUtils.CalculateECDHBasicAgreement(ecAgreePublicKey, ecAgreePrivateKey);
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
