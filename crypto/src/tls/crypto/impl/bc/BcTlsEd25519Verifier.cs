using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsEd25519Verifier
        : BcTlsVerifier
    {
        public BcTlsEd25519Verifier(BcTlsCrypto crypto, Ed25519PublicKeyParameters publicKey)
            : base(crypto, publicKey)
        {
        }

        public override bool VerifyRawSignature(DigitallySigned signature, byte[] hash)
        {
            throw new NotSupportedException();
        }

        public override TlsStreamVerifier GetStreamVerifier(DigitallySigned signature)
        {
            SignatureAndHashAlgorithm algorithm = signature.Algorithm;
            if (algorithm == null || SignatureScheme.From(algorithm) != SignatureScheme.ed25519)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            Ed25519Signer verifier = new Ed25519Signer();
            verifier.Init(false, m_publicKey);

            return new BcTlsStreamVerifier(verifier, signature.Signature);
        }
    }
}
