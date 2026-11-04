using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>BC light-weight base class for the verifiers supporting the two DSA style algorithms from FIPS PUB
    /// 186-4: DSA and ECDSA.</summary>
    public abstract class BcTlsDssVerifier
        : BcTlsVerifier
    {
        /// <summary>Create a new <see cref="BcTlsDssVerifier"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="publicKey">The public key.</param>
        protected BcTlsDssVerifier(BcTlsCrypto crypto, AsymmetricKeyParameter publicKey)
            : base(crypto, publicKey)
        {
        }

        /// <summary>Create the DSA implementation to use for verification.</summary>
        /// <returns>The DSA implementation.</returns>
        protected abstract IDsa CreateDsaImpl();

        /// <summary>Gets the signature algorithm.</summary>
        protected abstract short SignatureAlgorithm { get; }

        /// <inheritdoc/>
        public override bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm != null && algorithm.Signature != SignatureAlgorithm)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            ISigner signer = new DsaDigestSigner(CreateDsaImpl(), new NullDigest());
            signer.Init(false, m_publicKey);
            if (algorithm == null)
            {
                // Note: Only use the SHA1 part of the (MD5/SHA1) hash
                signer.BlockUpdate(hash, 16, 20);
            }
            else
            {
                signer.BlockUpdate(hash, 0, hash.Length);
            }
            return signer.VerifySignature(digitallySigned.Signature);
        }
    }
}
