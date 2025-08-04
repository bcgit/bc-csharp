using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>
    /// GOST VKO key agreement class - RFC 7836 Section 4.3 
    /// </summary>
    public class ECVKOAgreement
    {
        private readonly IDigest digest;

        private ECPrivateKeyParameters key;
        private BigInteger ukm;

        public int AgreementSize => this.digest.GetDigestSize();

        public ECVKOAgreement(IDigest digest)
        {
            this.digest = digest;
        }

        public void Init(ICipherParameters parameters)
        {
            if (!(parameters is ParametersWithUKM paramsWithUkm))
                throw new ArgumentException("ECVKOAgreement expects ParametersWithUKM");

            if (!(paramsWithUkm.GetParameters() is ECPrivateKeyParameters ecParams))
                throw new ArgumentException("ECVKOAgreement expects ParametersWithUKM contains ECPrivateKeyParameters");

            this.key = ecParams;
            this.ukm = new BigInteger(1, Arrays.Reverse(paramsWithUkm.GetUKM()));
        }

        public int GetFieldSize()
        {
            return this.key.Parameters.Curve.FieldElementEncodingLength;
        }

        public byte[] CalculateAgreement(ICipherParameters pubKey)
        {
            ECPublicKeyParameters pub = (ECPublicKeyParameters)pubKey;
            ECDomainParameters parameters = this.key.Parameters;

            if (!parameters.Equals(pub.Parameters))
            {
                throw new InvalidOperationException("ECVKO public key has wrong domain parameters");
            }

            BigInteger hd = parameters.H.Multiply(this.ukm).Multiply(this.key.D).Mod(parameters.N);

            // Always perform calculations on the exact curve specified by our private key's parameters
            ECPoint pubPoint = ECAlgorithms.CleanPoint(parameters.Curve, pub.Q);
            if (pubPoint.IsInfinity)
            {
                throw new InvalidOperationException("Infinity is not a valid public key for ECVKO");
            }

            ECPoint p = pubPoint.Multiply(hd).Normalize();

            if (p.IsInfinity)
            {
                throw new InvalidOperationException("Infinity is not a valid agreement value for ECVKO");
            }

            byte[] encoding = p.GetEncoded(false);
            int encodingLength = encoding.Length;
            int feSize = encodingLength / 2;

            Arrays.ReverseInPlace(encoding, encodingLength - (feSize * 2), feSize);
            Arrays.ReverseInPlace(encoding, encodingLength - feSize, feSize);

            byte[] rv = new byte[this.digest.GetDigestSize()];
            this.digest.BlockUpdate(encoding, encodingLength - (feSize * 2), feSize * 2);
            this.digest.DoFinal(rv, 0);
            return rv;
        }
    }
}
