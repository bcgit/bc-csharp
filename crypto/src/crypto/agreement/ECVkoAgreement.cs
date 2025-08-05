using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>
    /// GOST VKO key agreement class - RFC 7836 Section 4.3 
    /// </summary>
    public class ECVkoAgreement
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
                throw new ArgumentException("ECVKOAgreement expects ParametersWithUKM");

            if (!(paramsWithUkm.Parameters is ECPrivateKeyParameters ecParams))
                throw new ArgumentException("ECVKOAgreement expects ParametersWithUKM contains ECPrivateKeyParameters");

            m_key = ecParams;
            m_ukm = new BigInteger(1, paramsWithUkm.GetUkm(), bigEndian: false);
        }

        public int GetFieldSize()
        {
            return m_key.Parameters.Curve.FieldElementEncodingLength;
        }

        public byte[] CalculateAgreement(ICipherParameters pubKey)
        {
            ECPublicKeyParameters pub = (ECPublicKeyParameters)pubKey;
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
            int encodingLength = encoding.Length;
            int feSize = encodingLength / 2;

            Arrays.ReverseInPlace(encoding, encodingLength - (feSize * 2), feSize);
            Arrays.ReverseInPlace(encoding, encodingLength - feSize, feSize);

            return DigestUtilities.DoFinal(m_digest, encoding, encodingLength - (feSize * 2), feSize * 2);
        }
    }
}
