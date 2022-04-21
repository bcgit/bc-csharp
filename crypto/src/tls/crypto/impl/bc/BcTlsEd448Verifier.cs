using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsEd448Verifier
        : BcTlsVerifier
    {
        public BcTlsEd448Verifier(BcTlsCrypto crypto, Ed448PublicKeyParameters publicKey)
            : base(crypto, publicKey)
        {
        }

        public override TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm == null || SignatureScheme.From(algorithm) != SignatureScheme.ed448)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            Ed448Signer verifier = new Ed448Signer(TlsUtilities.EmptyBytes);
            verifier.Init(false, m_publicKey);

            return new BcTlsStreamVerifier(verifier, digitallySigned.Signature);
        }
    }
}
