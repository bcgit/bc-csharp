using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for generation of the raw DSA signature type using the BC light-weight API.
    /// </summary>
    public class BcTlsDsaSigner
        : BcTlsDssSigner
    {
        /// <summary>Create a new <see cref="BcTlsDsaSigner"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="privateKey">The private key.</param>
        public BcTlsDsaSigner(BcTlsCrypto crypto, DsaPrivateKeyParameters privateKey)
            : base(crypto, privateKey)
        {
        }

        /// <inheritdoc/>
        protected override IDsa CreateDsaImpl(int cryptoHashAlgorithm)
        {
            return new DsaSigner(new HMacDsaKCalculator(m_crypto.CreateDigest(cryptoHashAlgorithm)));
        }

        /// <inheritdoc/>
        protected override short SignatureAlgorithm
        {
            get { return Tls.SignatureAlgorithm.dsa; }
        }
    }
}
