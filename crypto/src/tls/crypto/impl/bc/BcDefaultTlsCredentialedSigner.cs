using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.</summary>
    public class BcDefaultTlsCredentialedSigner
        : DefaultTlsCredentialedSigner
    {
        private static BcTlsCertificate GetEndEntity(BcTlsCrypto crypto, Certificate certificate)
        {
            if (certificate == null || certificate.IsEmpty)
                throw new ArgumentException("No certificate");

            return BcTlsCertificate.Convert(crypto, certificate.GetCertificateAt(0));
        }

        private static TlsSigner MakeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey,
            Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            TlsSigner signer;
            if (privateKey is RsaKeyParameters)
            {
                RsaKeyParameters privKeyRsa = (RsaKeyParameters)privateKey;

                if (signatureAndHashAlgorithm != null)
                {
                    int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
                    if (SignatureScheme.IsRsaPss(signatureScheme))
                    {
                        return new BcTlsRsaPssSigner(crypto, privKeyRsa, signatureScheme);
                    }
                }

                RsaKeyParameters pubKeyRsa = GetEndEntity(crypto, certificate).GetPubKeyRsa();

                signer = new BcTlsRsaSigner(crypto, privKeyRsa, pubKeyRsa);
            }
            else if (privateKey is DsaPrivateKeyParameters)
            {
                signer = new BcTlsDsaSigner(crypto, (DsaPrivateKeyParameters)privateKey);
            }
            else if (privateKey is ECPrivateKeyParameters)
            {
                ECPrivateKeyParameters privKeyEC = (ECPrivateKeyParameters)privateKey;

                if (signatureAndHashAlgorithm != null)
                {
                    int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
                    if (SignatureScheme.IsECDsa(signatureScheme))
                    {
                        return new BcTlsECDsa13Signer(crypto, privKeyEC, signatureScheme);
                    }
                }

                signer = new BcTlsECDsaSigner(crypto, privKeyEC);
            }
            else if (privateKey is Ed25519PrivateKeyParameters)
            {
                signer = new BcTlsEd25519Signer(crypto, (Ed25519PrivateKeyParameters)privateKey);
            }
            else if (privateKey is Ed448PrivateKeyParameters)
            {
                signer = new BcTlsEd448Signer(crypto, (Ed448PrivateKeyParameters)privateKey);
            }
            else
            {
                throw new ArgumentException("'privateKey' type not supported: " + Platform.GetTypeName(privateKey));
            }

            return signer;
        }

        public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto,
            AsymmetricKeyParameter privateKey, Certificate certificate,
            SignatureAndHashAlgorithm signatureAndHashAlgorithm)
            : base(cryptoParams, MakeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate,
                signatureAndHashAlgorithm)
        {
        }
    }
}
