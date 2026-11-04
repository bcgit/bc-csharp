using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for the verification of the raw ECDSA signature type using the BC light-weight
    /// API.</summary>
    public class BcTlsECDsaVerifier
        : BcTlsDssVerifier
    {
        /// <summary>Create a new <see cref="BcTlsECDsaVerifier"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="publicKey">The public key.</param>
        public BcTlsECDsaVerifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey)
            : base(crypto, publicKey)
        {
        }

        /// <inheritdoc/>
        protected override IDsa CreateDsaImpl()
        {
            return new ECDsaSigner();
        }

        /// <inheritdoc/>
        protected override short SignatureAlgorithm
        {
            get { return Tls.SignatureAlgorithm.ecdsa; }
        }
    }
}
