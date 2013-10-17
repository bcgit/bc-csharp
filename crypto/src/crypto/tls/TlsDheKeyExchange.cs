using System;
using System.IO;

using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{
    internal class TlsDheKeyExchange
        : TlsDHKeyExchange
    {
        protected TlsSignerCredentials serverCredentials = null;

        public TlsDheKeyExchange(KeyExchangeAlgorithm keyExchange, IList supportedSignatureAlgorithms, DHParameters dhParameters)
            : base(keyExchange, supportedSignatureAlgorithms, dhParameters)
        {
        }

        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            if (!(serverCredentials is TlsSignerCredentials))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            ProcessServerCertificate(serverCredentials.Certificate);

            this.serverCredentials = (TlsSignerCredentials)serverCredentials;
        }

        public override byte[] GenerateServerKeyExchange()
        {
            if (this.dhParameters == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            MemoryStream buf = new MemoryStream();

            this.dhAgreeServerPrivateKey = TlsDHUtilities.GenerateEphemeralServerKeyExchange(context.SecureRandom,
                this.dhParameters, buf);

            byte[] digestInput = buf.ToArray();

            IDigest d = new CombinedHash();
            SecurityParameters securityParameters = context.SecurityParameters;
            d.BlockUpdate(securityParameters.clientRandom, 0, securityParameters.clientRandom.Length);
            d.BlockUpdate(securityParameters.serverRandom, 0, securityParameters.serverRandom.Length);
            d.BlockUpdate(digestInput, 0, digestInput.Length);

            byte[] hash = new byte[d.GetDigestSize()];
            d.DoFinal(hash, 0);

            byte[] signature = serverCredentials.GenerateCertificateSignature(hash);

            /*
             * TODO RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
             */
            DigitallySigned signed_params = new DigitallySigned(null, signature);
            signed_params.Encode(buf);

            return buf.ToArray();
        }

        public override void ProcessServerKeyExchange(Stream input)
        {
            SecurityParameters securityParameters = context.SecurityParameters;

            ISigner signer = InitVerifyer(tlsSigner, securityParameters);
            Stream sigIn = new SignerStream(input, signer, null);

            ServerDHParams pms = ServerDHParams.Parse(sigIn);

            DigitallySigned signed_params = DigitallySigned.Parse(context, input);

            if (!signer.VerifySignature(signed_params.Signature))
            {
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }

            this.dhAgreeServerPublicKey = TlsDHUtilities.ValidateDHPublicKey(pms.PublicKey);
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