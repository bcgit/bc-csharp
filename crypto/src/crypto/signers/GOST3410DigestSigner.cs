using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>Signer for GOST R 34.10, hashing the message with a digest before signing.</summary>
    public class Gost3410DigestSigner
        : ISigner
    {
        private readonly IDsa m_dsa;
        private readonly IDigest m_digest;
        private readonly int m_digestSize;

        private bool m_forSigning;

        /// <summary>Create a new <see cref="Gost3410DigestSigner"/>.</summary>
        /// <param name="signer">The signer.</param>
        /// <param name="digest">The digest.</param>
        // TODO[api] Rename 'signer' to 'dsa'
        public Gost3410DigestSigner(IDsa signer, IDigest digest)
        {
            m_dsa = signer ?? throw new ArgumentNullException(nameof(signer));
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));

            m_digestSize = digest.GetDigestSize();
        }

        /// <inheritdoc/>
        public virtual string AlgorithmName => m_digest.AlgorithmName + "with" + m_dsa.AlgorithmName;

        /// <inheritdoc/>
        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            m_forSigning = forSigning;

            var key = (AsymmetricKeyParameter)ParameterUtilities.IgnoreRandom(parameters);

            if (forSigning && !key.IsPrivate)
                throw new InvalidKeyException("Signing requires private key.");

            if (!forSigning && key.IsPrivate)
                throw new InvalidKeyException("Verification requires public key.");

            Reset();

            m_dsa.Init(forSigning, parameters);
        }

        /// <inheritdoc/>
        public virtual void Update(byte input) => m_digest.Update(input);

        /// <inheritdoc/>
        public virtual void BlockUpdate(byte[] input, int inOff, int inLen) =>
            m_digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public virtual void BlockUpdate(ReadOnlySpan<byte> input) => m_digest.BlockUpdate(input);
#endif

        /// <inheritdoc/>
        public virtual int GetMaxSignatureSize() => m_digestSize * 2;

        /// <inheritdoc/>
        public virtual byte[] GenerateSignature()
        {
            if (!m_forSigning)
                throw new InvalidOperationException("GOST3410DigestSigner not initialised for signature generation.");

            byte[] hash = DigestUtilities.DoFinal(m_digest);

            try
            {
                BigInteger[] rs = m_dsa.GenerateSignature(hash);

                int halfSize = m_digestSize, size = halfSize * 2;
                byte[] signature = new byte[size];
                BigIntegers.AsUnsignedByteArray(rs[1], signature, 0, halfSize);
                BigIntegers.AsUnsignedByteArray(rs[0], signature, halfSize, halfSize);
                return signature;
            }
            catch (Exception e)
            {
                throw new SignatureException(e.Message, e);
            }
        }

        /// <inheritdoc/>
        public virtual bool VerifySignature(byte[] signature)
        {
            if (m_forSigning)
                throw new InvalidOperationException("GOST3410DigestSigner not initialised for verification");

            byte[] hash = DigestUtilities.DoFinal(m_digest);

            BigInteger r, s;
            try
            {
                int halfSize = m_digestSize;
                r = new BigInteger(1, signature, halfSize, halfSize);
                s = new BigInteger(1, signature, 0, halfSize);
            }
            catch (Exception e)
            {
                throw new SignatureException("error decoding signature bytes.", e);
            }

            return m_dsa.VerifySignature(hash, r, s);
        }

        /// <inheritdoc/>
        public virtual void Reset() => m_digest.Reset();
    }
}
