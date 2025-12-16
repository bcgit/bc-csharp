using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>DSTU 4145-2002</summary>
    /// <remarks>
    /// National Ukrainian standard of digital signature based on elliptic curves (DSTU 4145-2002).
    /// </remarks>
    public class Dstu4145Signer
        : IDsa
    {
        private ECKeyParameters m_key;
        private SecureRandom m_random;

        public virtual string AlgorithmName => "DSTU4145";

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            if (forSigning)
            {
                parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

                if (!(parameters is ECPrivateKeyParameters ecPrivateKeyParameters))
                    throw new InvalidKeyException("EC private key required for signing");

                m_key = ecPrivateKeyParameters;
                m_random = CryptoServicesRegistrar.GetSecureRandom(providedRandom);
            }
            else
            {
                if (!(parameters is ECPublicKeyParameters ecPublicKeyParameters))
                    throw new InvalidKeyException("EC public key required for verification");

                m_key = ecPublicKeyParameters;
                m_random = null;
            }
        }

        public virtual BigInteger Order => m_key.Parameters.N;

        public virtual BigInteger[] GenerateSignature(byte[] message)
        {
            ECDomainParameters ec = m_key.Parameters;

            ECCurve curve = ec.Curve;

            ECFieldElement h = Hash2FieldElement(curve, message);
            if (h.IsZero)
            {
                h = curve.FromBigInteger(BigInteger.One);
            }

            BigInteger n = ec.N;
            BigInteger e, r, s;
            ECFieldElement Fe, y;

            BigInteger d = ((ECPrivateKeyParameters)m_key).D;

            ECMultiplier basePointMultiplier = CreateBasePointMultiplier();

            do
            {
                do
                {
                    do
                    {
                        e = BigIntegers.CreateRandomInRange(BigInteger.One, n.Subtract(BigInteger.One), m_random);
                        Fe = basePointMultiplier.Multiply(ec.G, e).Normalize().AffineXCoord;
                    }
                    while (Fe.IsZero);

                    y = h.Multiply(Fe);
                    r = FieldElement2Integer(n, y);
                }
                while (r.SignValue < 1);

                s = r.Multiply(d).Add(e).Mod(n);
            }
            while (s.SignValue < 1);

            return new BigInteger[]{ r, s };
        }

        public virtual bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
        {
            ECDomainParameters parameters = m_key.Parameters;
            BigInteger n = parameters.N;

            if (r.SignValue < 1 || s.SignValue < 1 || r.CompareTo(n) >= 0 || s.CompareTo(n) >= 0)
                return false;

            ECCurve curve = parameters.Curve;

            ECFieldElement h = Hash2FieldElement(curve, message);
            if (h.IsZero)
            {
                h = curve.FromBigInteger(BigInteger.One);
            }

            ECPoint G = parameters.G;
            ECPoint Q = ((ECPublicKeyParameters)m_key).Q;

            ECPoint R = ECAlgorithms.SumOfTwoMultiplies(G, s, Q, r);

            if (R.IsInfinity)
                return false;

            ECFieldElement y = h.Multiply(R.Normalize().AffineXCoord);
            return FieldElement2Integer(n, y).Equals(r);
        }

        protected virtual ECMultiplier CreateBasePointMultiplier() => new FixedPointCombMultiplier();

        private static ECFieldElement Hash2FieldElement(ECCurve curve, byte[] hash)
        {
            byte[] data = Arrays.Reverse(hash);
            return curve.FromBigInteger(Truncate(new BigInteger(1, data), curve.FieldSize));
        }

        private static BigInteger FieldElement2Integer(BigInteger n, ECFieldElement fe)
        {
            return Truncate(fe.ToBigInteger(), n.BitLength - 1);
        }

        private static BigInteger Truncate(BigInteger x, int bitLength)
        {
            if (x.BitLength > bitLength)
            {
                x = x.Mod(BigInteger.One.ShiftLeft(bitLength));
            }
            return x;
        }
    }
}
