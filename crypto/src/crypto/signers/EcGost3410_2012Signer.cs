using Org.BouncyCastle.Math;
using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class ECGOST3410_2012Signer : IDsaExt
    {
        private ECKeyParameters key;
        private SecureRandom secureRandom;
        private bool forSigning;

        public BigInteger Order
        {
            get { return key.Parameters.N; }
        }

        public string AlgorithmName
        {
            get { return key.AlgorithmName; }
        }

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            this.forSigning = forSigning;
            if (forSigning)
            {
                if (parameters is ParametersWithRandom)
                {
                    ParametersWithRandom rParam = (ParametersWithRandom)parameters;
                    this.secureRandom = rParam.Random;
                    this.key = (ECPrivateKeyParameters)rParam.Parameters;
                }
                else
                {
                    this.secureRandom = new SecureRandom();
                    this.key = (ECPrivateKeyParameters)parameters;
                }
            }
            else
            {
                this.key = (ECPublicKeyParameters)parameters;
            }
        } 

        public BigInteger[] GenerateSignature(byte[] message)
        {
            if (!forSigning)
            {
                throw new InvalidOperationException("not initialized for signing");
            }

            byte[] mRev = new byte[message.Length]; // conversion is little-endian
            for (int i = 0; i != mRev.Length; i++)
            {
                mRev[i] = message[mRev.Length - 1 - i];
            }
            BigInteger e = new BigInteger(1, mRev);

            ECDomainParameters ec = key.Parameters;
            BigInteger n = ec.N;
            BigInteger d = ((ECPrivateKeyParameters)key).D;

            BigInteger r, s;

            ECMultiplier basePointMultiplier = CreateBasePointMultiplier();

            do // generate s
            {
                BigInteger k;
                do // generate r
                {
                    do
                    {
                        k = BigIntegers.CreateRandomBigInteger(n.BitLength, secureRandom);
                    }
                    while (k.Equals(BigInteger.Zero)); //  ECConstants.ZERO));

                    ECPoint p = basePointMultiplier.Multiply(ec.G, k).Normalize();

                    r = p.AffineXCoord.ToBigInteger().Mod(n);
                }
                while (r.Equals(BigInteger.Zero)); //  ECConstants.ZERO));

                s = (k.Multiply(e)).Add(d.Multiply(r)).Mod(n);
            }
            while (s.Equals(BigInteger.Zero)); //   ECConstants.ZERO));

            return new BigInteger[] { r, s };
        }


        public bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
        {
            if (forSigning)
            {
                throw new InvalidOperationException("not initialized for verification");
            }


            byte[] mRev = new byte[message.Length]; // conversion is little-endian
            for (int i = 0; i != mRev.Length; i++)
            {
                mRev[i] = message[mRev.Length - 1 - i];
            }
            BigInteger e = new BigInteger(1, mRev);
            BigInteger n = key.Parameters.N;

            // r in the range [1,n-1]
            if (r.CompareTo(BigInteger.One) < 0 || r.CompareTo(n) >= 0)
            {
                return false;
            }

            // s in the range [1,n-1]
            if (s.CompareTo(BigInteger.One) < 0 || s.CompareTo(n) >= 0)
            {
                return false;
            }

            BigInteger v = e.ModInverse(n);

            BigInteger z1 = s.Multiply(v).Mod(n);
            BigInteger z2 = (n.Subtract(r)).Multiply(v).Mod(n);

            ECPoint G = key.Parameters.G; // P
            ECPoint Q = ((ECPublicKeyParameters)key).Q;

            ECPoint point = ECAlgorithms.SumOfTwoMultiplies(G, z1, Q, z2).Normalize();

            // components must be bogus.
            if (point.IsInfinity)
            {
                return false;
            }

            BigInteger R = point.AffineXCoord.ToBigInteger().Mod(n);

            return R.Equals(r);
        }

        protected virtual ECMultiplier CreateBasePointMultiplier()
        {
            return new FixedPointCombMultiplier();
        }
    }
}