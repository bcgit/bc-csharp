using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Signers
{
    /**
     * EC-DSA as described in X9.62
     */
    public class ECDsaSigner
        : IDsa
    {
        private ECKeyParameters key;
        private SecureRandom random;

        public string AlgorithmName
        {
            get { return "ECDSA"; }
        }

        public void Init(
            bool				forSigning,
            ICipherParameters	parameters)
        {
            if (forSigning)
            {
                if (parameters is ParametersWithRandom)
                {
                    ParametersWithRandom rParam = (ParametersWithRandom) parameters;

                    this.random = rParam.Random;
                    parameters = rParam.Parameters;
                }
                else
                {
                    this.random = new SecureRandom();
                }

                if (!(parameters is ECPrivateKeyParameters))
                    throw new InvalidKeyException("EC private key required for signing");

                this.key = (ECPrivateKeyParameters) parameters;
            }
            else
            {
                if (!(parameters is ECPublicKeyParameters))
                    throw new InvalidKeyException("EC public key required for verification");

                this.key = (ECPublicKeyParameters) parameters;
            }
        }

        // 5.3 pg 28
        /**
         * Generate a signature for the given message using the key we were
         * initialised with. For conventional DSA the message should be a SHA-1
         * hash of the message of interest.
         *
         * @param message the message that will be verified later.
         */
        public BigInteger[] GenerateSignature(byte[] message)
        {
            ECDomainParameters ec = key.Parameters;
            BigInteger n = ec.N;
            BigInteger e = CalculateE(n, message);
            BigInteger d = ((ECPrivateKeyParameters)key).D;

            BigInteger r, s;

            ECMultiplier basePointMultiplier = CreateBasePointMultiplier();

            // 5.3.2
            do // Generate s
            {
                BigInteger k;
                do // Generate r
                {
                    do
                    {
                        k = new BigInteger(n.BitLength, random);
                    }
                    while (k.SignValue == 0 || k.CompareTo(n) >= 0);

                    ECPoint p = basePointMultiplier.Multiply(ec.G, k).Normalize();

                    // 5.3.3
                    r = p.AffineXCoord.ToBigInteger().Mod(n);
                }
                while (r.SignValue == 0);

                s = k.ModInverse(n).Multiply(e.Add(d.Multiply(r))).Mod(n);
            }
            while (s.SignValue == 0);

            return new BigInteger[]{ r, s };
        }

        // 5.4 pg 29
        /**
         * return true if the value r and s represent a DSA signature for
         * the passed in message (for standard DSA the message should be
         * a SHA-1 hash of the real message to be verified).
         */
        public bool VerifySignature(
            byte[]		message,
            BigInteger	r,
            BigInteger	s)
        {
            BigInteger n = key.Parameters.N;

            // r and s should both in the range [1,n-1]
            if (r.SignValue < 1 || s.SignValue < 1
                || r.CompareTo(n) >= 0 || s.CompareTo(n) >= 0)
            {
                return false;
            }

            BigInteger e = CalculateE(n, message);
            BigInteger c = s.ModInverse(n);

            BigInteger u1 = e.Multiply(c).Mod(n);
            BigInteger u2 = r.Multiply(c).Mod(n);

            ECPoint G = key.Parameters.G;
            ECPoint Q = ((ECPublicKeyParameters) key).Q;

            ECPoint point = ECAlgorithms.SumOfTwoMultiplies(G, u1, Q, u2).Normalize();

            if (point.IsInfinity)
                return false;

            BigInteger v = point.AffineXCoord.ToBigInteger().Mod(n);

            return v.Equals(r);
        }

        protected virtual BigInteger CalculateE(BigInteger n, byte[] message)
        {
            int messageBitLength = message.Length * 8;
            BigInteger trunc = new BigInteger(1, message);

            if (n.BitLength < messageBitLength)
            {
                trunc = trunc.ShiftRight(messageBitLength - n.BitLength);
            }

            return trunc;
        }

        protected virtual ECMultiplier CreateBasePointMultiplier()
        {
            return new FixedPointCombMultiplier();
        }
    }
}
