using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>
    /// GOST VKO key agreement class - RFC 7836 Section 4.3 
    /// </summary>
    public sealed class ECVkoAgreement
        : IRawAgreement
    {
        private readonly IDigest m_digest;

        private ECPrivateKeyParameters m_key;
        private BigInteger m_ukm;

        public int AgreementSize => m_digest.GetDigestSize();

        public ECVkoAgreement(IDigest digest)
        {
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));
        }

        public void Init(ICipherParameters parameters)
        {
            if (!(parameters is ParametersWithUkm paramsWithUkm))
                throw new ArgumentException($"{nameof(ECVkoAgreement)} expects {nameof(ParametersWithUkm)}");

            if (!(paramsWithUkm.Parameters is ECPrivateKeyParameters ecParams))
                throw new ArgumentException($"{nameof(ECVkoAgreement)} expects {nameof(ECPrivateKeyParameters)}");

            m_key = ecParams;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            m_ukm = new BigInteger(1, paramsWithUkm.InternalUkm, bigEndian: false);
#else
            m_ukm = new BigInteger(1, paramsWithUkm.GetUkm(), bigEndian: false);
#endif
        }

        public void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CalculateAgreement(publicKey, buf.AsSpan(off));
#else
            ImplUpdateDigest(publicKey);
            m_digest.DoFinal(buf, off);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void CalculateAgreement(ICipherParameters publicKey, Span<byte> buf)
        {
            ImplUpdateDigest(publicKey);
            m_digest.DoFinal(buf);
        }
#endif

        private void ImplUpdateDigest(ICipherParameters publicKey)
        {
            ECPublicKeyParameters pub = (ECPublicKeyParameters)publicKey;
            ECDomainParameters parameters = m_key.Parameters;

            if (!parameters.Equals(pub.Parameters))
                throw new InvalidOperationException("ECVKO public key has wrong domain parameters");

            BigInteger hd = parameters.H.Multiply(m_ukm).Multiply(m_key.D).Mod(parameters.N);

            // Always perform calculations on the exact curve specified by our private key's parameters
            ECPoint pubPoint = ECAlgorithms.CleanPoint(parameters.Curve, pub.Q);
            if (pubPoint.IsInfinity)
                throw new InvalidOperationException("Infinity is not a valid public key for ECVKO");

            ECPoint p = pubPoint.Multiply(hd).Normalize();

            if (p.IsInfinity)
                throw new InvalidOperationException("Infinity is not a valid agreement value for ECVKO");

            byte[] encoding = p.GetEncoded(compressed: false);
            int feSize = encoding.Length / 2;

            Arrays.ReverseInPlace(encoding, 1, feSize);
            Arrays.ReverseInPlace(encoding, 1 + feSize, feSize);

            m_digest.BlockUpdate(encoding, 1, feSize * 2);
        }
    }
}
