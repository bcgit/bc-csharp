using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{
	/// <summary>
	/// TLS 1.1 SRP key exchange.
	/// </summary>
    internal class TlsSrpKeyExchange
        : AbstractTlsKeyExchange
    {
        protected TlsSigner tlsSigner;
        protected byte[] identity;
        protected byte[] password;

        protected AsymmetricKeyParameter serverPublicKey = null;

        protected byte[] s = null;
        protected BigInteger B = null;
        protected Srp6Client srpClient = new Srp6Client();

        public TlsSrpKeyExchange(KeyExchangeAlgorithm keyExchange, IList supportedSignatureAlgorithms, byte[] identity, byte[] password)
            : base(keyExchange, supportedSignatureAlgorithms)
        {
            switch (keyExchange)
            {
                case KeyExchangeAlgorithm.SRP:
                    this.tlsSigner = null;
                    break;
                case KeyExchangeAlgorithm.SRP_RSA:
                    this.tlsSigner = new TlsRsaSigner();
                    break;
                case KeyExchangeAlgorithm.SRP_DSS:
                    this.tlsSigner = new TlsDssSigner();
                    break;
                default:
                    throw new ArgumentException("unsupported key exchange algorithm", "keyExchange");
            }

            this.keyExchange = keyExchange;
            this.identity = identity;
            this.password = password;
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
            if (tlsSigner != null)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            if (tlsSigner == null)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

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

            if (!tlsSigner.IsValidPublicKey(this.serverPublicKey))
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }

            TlsUtilities.ValidateKeyUsage(x509Cert, KeyUsage.DigitalSignature);
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
                return true;
            }
        }

        public override void ProcessServerKeyExchange(Stream input)
        {
            SecurityParameters securityParameters = context.SecurityParameters;

            Stream sigIn = input;
            ISigner signer = null;

            if (tlsSigner != null)
            {
                signer = InitVerifyer(tlsSigner, securityParameters);
                sigIn = new SignerStream(input, signer, null);
            }

            byte[] NBytes = TlsUtilities.ReadOpaque16(sigIn);
            byte[] gBytes = TlsUtilities.ReadOpaque16(sigIn);
            byte[] sBytes = TlsUtilities.ReadOpaque8(sigIn);
            byte[] BBytes = TlsUtilities.ReadOpaque16(sigIn);

            if (signer != null)
            {
                DigitallySigned signed_params = DigitallySigned.Parse(context, input);

                if (!signer.VerifySignature(signed_params.Signature))
                {
                    throw new TlsFatalAlert(AlertDescription.decrypt_error);
                }
            }

            BigInteger N = new BigInteger(1, NBytes);
            BigInteger g = new BigInteger(1, gBytes);

            // TODO Validate group parameters (see RFC 5054)
            //throw new TlsFatalAlert(AlertDescription.insufficient_security);

            this.s = sBytes;

            /*
            * RFC 5054 2.5.3: The client MUST abort the handshake with an "illegal_parameter"
            * alert if B % N = 0.
            */
            try
            {
                this.B = Srp6Utilities.ValidatePublicValue(N, new BigInteger(1, BBytes));
            }
            catch (CryptoException)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.srpClient.Init(N, g, new Sha1Digest(), context.SecureRandom);
        }

        public override void ValidateCertificateRequest(CertificateRequest certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        public override void ProcessClientCredentials(TlsCredentials clientCredentials)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public override void GenerateClientKeyExchange(Stream output)
        {
            BigInteger A = srpClient.GenerateClientCredentials(s, this.identity, this.password);
            TlsUtilities.WriteOpaque16(BigIntegers.AsUnsignedByteArray(A), output);
        }

        public override byte[] GeneratePremasterSecret()
        {
            try
            {
                // TODO Check if this needs to be a fixed size
                return BigIntegers.AsUnsignedByteArray(srpClient.CalculateSecret(B));
            }
            catch (CryptoException)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        protected ISigner InitVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters)
        {
            ISigner signer = tlsSigner.CreateVerifyer(this.serverPublicKey);
            signer.BlockUpdate(securityParameters.clientRandom, 0, securityParameters.clientRandom.Length);
            signer.BlockUpdate(securityParameters.serverRandom, 0, securityParameters.serverRandom.Length);
            return signer;
        }
    }
}
