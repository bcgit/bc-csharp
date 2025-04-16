using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.</summary>
    public class BcDefaultTlsCredentialedSigner
        : DefaultTlsCredentialedSigner
    {
        private static TlsSigner MakeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey,
            Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            if (privateKey is RsaKeyParameters rsaPrivateKey)
            {
                if (signatureAndHashAlgorithm != null)
                {
                    int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
                    if (SignatureScheme.IsRsaPss(signatureScheme))
                        return new BcTlsRsaPssSigner(crypto, rsaPrivateKey, signatureScheme);
                }

                return new BcTlsRsaSigner(crypto, rsaPrivateKey);
            }
            else if (privateKey is DsaPrivateKeyParameters dsaPrivateKey)
            {
                return new BcTlsDsaSigner(crypto, dsaPrivateKey);
            }
            else if (privateKey is ECPrivateKeyParameters ecPrivateKey)
            {
                if (signatureAndHashAlgorithm != null)
                {
                    int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
                    if (SignatureScheme.IsECDsa(signatureScheme))
                        return new BcTlsECDsa13Signer(crypto, ecPrivateKey, signatureScheme);
                }

                return new BcTlsECDsaSigner(crypto, ecPrivateKey);
            }
            else if (privateKey is Ed25519PrivateKeyParameters ed25519PrivateKey)
            {
                return new BcTlsEd25519Signer(crypto, ed25519PrivateKey);
            }
            else if (privateKey is Ed448PrivateKeyParameters ed448PrivateKey)
            {
                return new BcTlsEd448Signer(crypto, ed448PrivateKey);
            }
            else if (privateKey is MLDsaPrivateKeyParameters mlDsaPrivateKey)
            {
                if (signatureAndHashAlgorithm != null)
                {
                    int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
                    TlsSigner signer = BcTlsMLDsaSigner.Create(crypto, mlDsaPrivateKey, signatureScheme);
                    if (signer != null)
                        return signer;
                }

                throw new ArgumentException("ML-DSA private key of wrong type for signature algorithm");
            }
            else
            {
                throw new ArgumentException("'privateKey' type not supported: " + privateKey.GetType().FullName);
            }
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
