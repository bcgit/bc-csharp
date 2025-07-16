using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class GenericSigner
        : ISigner
    {
        private readonly IAsymmetricBlockCipher m_engine;
        private readonly IDigest m_digest;
        private bool m_forSigning;

        public GenericSigner(IAsymmetricBlockCipher engine, IDigest digest)
        {
            m_engine = engine;
            m_digest = digest;
        }

        public virtual string AlgorithmName => $"Generic({m_engine.AlgorithmName}/{m_digest.AlgorithmName})";

        /**
         * initialise the signer for signing or verification.
         *
         * @param forSigning
         *            true if for signing, false otherwise
         * @param parameters
         *            necessary parameters.
         */
        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            m_forSigning = forSigning;

            AsymmetricKeyParameter key = (AsymmetricKeyParameter)ParameterUtilities.IgnoreRandom(parameters);

            if (forSigning && !key.IsPrivate)
                throw new InvalidKeyException("Signing requires private key.");

            if (!forSigning && key.IsPrivate)
                throw new InvalidKeyException("Verification requires public key.");

            Reset();

            m_engine.Init(forSigning, parameters);
        }

        public virtual void Update(byte input) => m_digest.Update(input);

        public virtual void BlockUpdate(byte[] input, int inOff, int inLen) =>
            m_digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void BlockUpdate(ReadOnlySpan<byte> input) => m_digest.BlockUpdate(input);
#endif

        public virtual int GetMaxSignatureSize() => m_engine.GetOutputBlockSize();

        public virtual byte[] GenerateSignature()
        {
            if (!m_forSigning)
                throw new InvalidOperationException("GenericSigner not initialised for signature generation.");

            byte[] hash = DigestUtilities.DoFinal(m_digest);

            return m_engine.ProcessBlock(hash, 0, hash.Length);
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (m_forSigning)
                throw new InvalidOperationException("GenericSigner not initialised for verification");

            byte[] hash = DigestUtilities.DoFinal(m_digest);

            try
            {
                byte[] sig = m_engine.ProcessBlock(signature, 0, signature.Length);

                // Extend with leading zeroes to match the digest size, if necessary.
                if (sig.Length < hash.Length)
                {
                    byte[] tmp = new byte[hash.Length];
                    Array.Copy(sig, 0, tmp, tmp.Length - sig.Length, sig.Length);
                    sig = tmp;
                }

                return Arrays.FixedTimeEquals(sig, hash);
            }
            catch
            {
                return false;
            }
        }

        public virtual void Reset() => m_digest.Reset();
    }
}
