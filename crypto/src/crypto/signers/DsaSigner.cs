using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Signers
{
    /**
     * The Digital Signature Algorithm - as described in "Handbook of Applied
     * Cryptography", pages 452 - 453.
     */
    public class DsaSigner
        : IDsa
    {
        protected DsaKeyParameters key = null;
        protected SecureRandom random = null;

        public virtual string AlgorithmName
        {
            get { return "DSA"; }
        }

        public virtual void Init(bool forSigning, ICipherParameters	parameters)
        {
            SecureRandom providedRandom = null;

            if (forSigning)
            {
                if (parameters is ParametersWithRandom)
                {
                    ParametersWithRandom rParam = (ParametersWithRandom)parameters;

                    providedRandom = rParam.Random;
                    parameters = rParam.Parameters;
                }

                if (!(parameters is DsaPrivateKeyParameters))
                    throw new InvalidKeyException("DSA private key required for signing");

                this.key = (DsaPrivateKeyParameters)parameters;
            }
            else
            {
                if (!(parameters is DsaPublicKeyParameters))
                    throw new InvalidKeyException("DSA public key required for verification");

                this.key = (DsaPublicKeyParameters)parameters;
            }

            this.random = InitSecureRandom(forSigning, providedRandom);
        }

        /**
         * Generate a signature for the given message using the key we were
         * initialised with. For conventional DSA the message should be a SHA-1
         * hash of the message of interest.
         *
         * @param message the message that will be verified later.
         */
        public virtual BigInteger[] GenerateSignature(byte[] message)
        {
            DsaParameters parameters = key.Parameters;
            BigInteger q = parameters.Q;
            BigInteger m = CalculateE(q, message);
            BigInteger k;

            do
            {
                k = new BigInteger(q.BitLength, random);
            }
            while (k.CompareTo(q) >= 0);

            BigInteger r = parameters.G.ModPow(k, parameters.P).Mod(q);

            k = k.ModInverse(q).Multiply(
                m.Add(((DsaPrivateKeyParameters)key).X.Multiply(r)));

            BigInteger s = k.Mod(q);

            return new BigInteger[]{ r, s };
        }

        /**
         * return true if the value r and s represent a DSA signature for
         * the passed in message for standard DSA the message should be a
         * SHA-1 hash of the real message to be verified.
         */
        public virtual bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
        {
            DsaParameters parameters = key.Parameters;
            BigInteger q = parameters.Q;
            BigInteger m = CalculateE(q, message);

            if (r.SignValue <= 0 || q.CompareTo(r) <= 0)
            {
                return false;
            }

            if (s.SignValue <= 0 || q.CompareTo(s) <= 0)
            {
                return false;
            }

            BigInteger w = s.ModInverse(q);

            BigInteger u1 = m.Multiply(w).Mod(q);
            BigInteger u2 = r.Multiply(w).Mod(q);

            BigInteger p = parameters.P;
            u1 = parameters.G.ModPow(u1, p);
            u2 = ((DsaPublicKeyParameters)key).Y.ModPow(u2, p);

            BigInteger v = u1.Multiply(u2).Mod(p).Mod(q);

            return v.Equals(r);
        }

        protected virtual BigInteger CalculateE(BigInteger n, byte[] message)
        {
            int length = System.Math.Min(message.Length, n.BitLength / 8);

            return new BigInteger(1, message, 0, length);
        }

        protected virtual SecureRandom InitSecureRandom(bool needed, SecureRandom provided)
        {
            return !needed ? null : (provided != null) ? provided : new SecureRandom();
        }
    }
}
