using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class DsaDigestSigner
        : ISigner
    {
        private readonly IDsa m_dsa;
        private readonly IDigest m_digest;
        private readonly IDsaEncoding m_encoding;
        private bool m_forSigning;

        public DsaDigestSigner(IDsa dsa, IDigest digest)
            : this(dsa, digest, StandardDsaEncoding.Instance)
        {
        }

        public DsaDigestSigner(IDsa dsa, IDigest digest, IDsaEncoding encoding)
        {
            m_dsa = dsa;
            m_digest = digest;
            m_encoding = encoding;
        }

        public virtual string AlgorithmName => m_digest.AlgorithmName + "with" + m_dsa.AlgorithmName;

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            m_forSigning = forSigning;

            AsymmetricKeyParameter k = (AsymmetricKeyParameter)ParameterUtilities.IgnoreRandom(parameters);

            if (forSigning && !k.IsPrivate)
                throw new InvalidKeyException("Signing requires private key.");

            if (!forSigning && k.IsPrivate)
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

        public virtual int GetMaxSignatureSize() => m_encoding.GetMaxEncodingSize(GetOrder());

        public virtual byte[] GenerateSignature()
        {
            if (!m_forSigning)
                throw new InvalidOperationException("DsaDigestSigner not initialized for signature generation.");

            byte[] hash = new byte[m_digest.GetDigestSize()];
            m_digest.DoFinal(hash, 0);

            BigInteger[] sig = m_dsa.GenerateSignature(hash);

            try
            {
                return m_encoding.Encode(GetOrder(), sig[0], sig[1]);
            }
            catch (Exception)
            {
                throw new InvalidOperationException("unable to encode signature");
            }
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (m_forSigning)
                throw new InvalidOperationException("DsaDigestSigner not initialized for verification");

            byte[] hash = new byte[m_digest.GetDigestSize()];
            m_digest.DoFinal(hash, 0);

            try
            {
                BigInteger[] sig = m_encoding.Decode(GetOrder(), signature);

                return m_dsa.VerifySignature(hash, sig[0], sig[1]);
            }
            catch (Exception)
            {
                return false;
            }
        }

        public virtual void Reset() => m_digest.Reset();

        protected virtual BigInteger GetOrder() => m_dsa.Order;
    }
}
