using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Tls
{
    /**
    * ECDHE key exchange (see RFC 4492)
    */
    internal class TlsECDheKeyExchange : TlsECDHKeyExchange
    {
        protected TlsSignerCredentials serverCredentials = null;

        public TlsECDheKeyExchange(KeyExchangeAlgorithm keyExchange, IList supportedSignatureAlgorithms, NamedCurve[] namedCurves,
            ECPointFormat[] clientECPointFormats, ECPointFormat[] serverECPointFormats)
            : base(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats)
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
            /*
             * First we try to find a supported named curve from the client's list.
             */
            NamedCurve namedCurve = NamedCurve.unassigned;

            if (namedCurves == null)
            {
                namedCurve = NamedCurve.secp256r1;
            }
            else
            {
                for (int i = 0; i < namedCurves.Length; ++i)
                {
                    NamedCurve entry = namedCurves[i];
                    if (TlsECCUtils.IsSupportedNamedCurve(entry))
                    {
                        namedCurve = entry;
                        break;
                    }
                }
            }

            ECDomainParameters curve_params = null;
            if (namedCurve >= 0)
            {
                curve_params = TlsECCUtils.GetParametersForNamedCurve(namedCurve);
            }
            else
            {
                /*
                 * If no named curves are suitable, check if the client supports explicit curves.
                 */
                if (TlsProtocol.ArrayContains(namedCurves, NamedCurve.arbitrary_explicit_prime_curves))
                {
                    curve_params = TlsECCUtils.GetParametersForNamedCurve(NamedCurve.secp256r1);
                }
                else if (TlsProtocol.ArrayContains(namedCurves, NamedCurve.arbitrary_explicit_char2_curves))
                {
                    curve_params = TlsECCUtils.GetParametersForNamedCurve(NamedCurve.sect233r1);
                }
            }

            if (curve_params == null)
            {
                /*
                 * NOTE: We shouldn't have negotiated ECDHE key exchange since we apparently can't find
                 * a suitable curve.
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            AsymmetricCipherKeyPair kp = TlsECCUtils.GenerateECKeyPair(context.SecureRandom, curve_params);
            this.ecAgreePrivateKey = (ECPrivateKeyParameters)kp.Private;

            MemoryStream buf = new MemoryStream();

            if (namedCurve < 0)
            {
                TlsECCUtils.WriteExplicitECParameters(clientECPointFormats, curve_params, buf);
            }
            else
            {
                TlsECCUtils.WriteNamedECParameters(namedCurve, buf);
            }

            ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters)kp.Public;
            TlsECCUtils.WriteECPoint(clientECPointFormats, ecPublicKey.Q, buf);

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

            ECDomainParameters curve_params = TlsECCUtils.ReadECParameters(namedCurves, clientECPointFormats, sigIn);

            byte[] point = TlsUtilities.ReadOpaque8(sigIn);

            DigitallySigned signed_params = DigitallySigned.Parse(context, input);

            if (!signer.VerifySignature(signed_params.Signature))
            {
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }

            this.ecAgreePublicKey = TlsECCUtils.ValidateECPublicKey(TlsECCUtils.DeserializeECPublicKey(
                clientECPointFormats, curve_params, point));
        }

        public override void ValidateCertificateRequest(CertificateRequest certificateRequest)
        {
            /*
             * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
             * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
             * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
             * these algorithms.
             */
            var types = certificateRequest.CertificateTypes;
            for (int i = 0; i < types.Length; ++i)
            {
                switch (types[i])
                {
                    case ClientCertificateType.rsa_sign:
                    case ClientCertificateType.dss_sign:
                    case ClientCertificateType.ecdsa_sign:
                        break;
                    default:
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        public override void ProcessClientCredentials(TlsCredentials clientCredentials)
        {
            if (clientCredentials is TlsSignerCredentials)
            {
                // OK
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
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
