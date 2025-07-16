using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class Gost3410DigestSigner
        : ISigner
    {
        private readonly IDsa m_dsa;
        private readonly IDigest m_digest;
        private readonly int m_digestSize;

        private bool m_forSigning;

        // TODO[api] Rename 'signer' to 'dsa'
        public Gost3410DigestSigner(IDsa signer, IDigest digest)
        {
            m_dsa = signer ?? throw new ArgumentNullException(nameof(signer));
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));

            m_digestSize = digest.GetDigestSize();
        }

        public virtual string AlgorithmName => m_digest.AlgorithmName + "with" + m_dsa.AlgorithmName;

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

        public virtual void Update(byte input) => m_digest.Update(input);

        public virtual void BlockUpdate(byte[] input, int inOff, int inLen) =>
            m_digest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void BlockUpdate(ReadOnlySpan<byte> input) => m_digest.BlockUpdate(input);
#endif

        public virtual int GetMaxSignatureSize() => m_digestSize * 2;

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

        public virtual void Reset() => m_digest.Reset();
    }
}
