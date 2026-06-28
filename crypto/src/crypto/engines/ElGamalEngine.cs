using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>This does your basic ElGamal algorithm.</summary>
    public class ElGamalEngine
        : IAsymmetricBlockCipher
    {
        private ElGamalKeyParameters key;
        private SecureRandom random;
        private bool forEncryption;
        private int bitSize;

        public virtual string AlgorithmName => "ElGamal";

        /// <summary>Initialise the ElGamal engine.</summary>
        /// <param name="forEncryption"><c>true</c> if we are encrypting, <c>false</c> otherwise.</param>
        /// <param name="parameters">the necessary ElGamal key parameters.</param>
        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.key = (ElGamalKeyParameters)ParameterUtilities.GetRandom(parameters, out var providedRandom);
            this.random = forEncryption ? CryptoServicesRegistrar.GetSecureRandom(providedRandom) : null;

            this.forEncryption = forEncryption;
            this.bitSize = key.Parameters.P.BitLength;

            if (forEncryption)
            {
                if (!(key is ElGamalPublicKeyParameters))
                    throw new ArgumentException("ElGamalPublicKeyParameters are required for encryption.");
            }
            else
            {
                if (!(key is ElGamalPrivateKeyParameters))
                    throw new ArgumentException("ElGamalPrivateKeyParameters are required for decryption.");
            }
        }

        /// <summary>Return the maximum size for an input block to this engine.</summary>
        /// <remarks>
        /// For ElGamal this is always one byte less than the size of P on encryption, and twice the length as the size
        /// of P on decryption.
        /// </remarks>
        /// <returns>maximum size for an input block.</returns>
        public virtual int GetInputBlockSize()
        {
            if (forEncryption)
                return (bitSize - 1) / 8;

            return 2 * ((bitSize + 7) / 8);
        }

        /// <summary>Return the maximum size for an output block to this engine.</summary>
        /// <remarks>
        /// For ElGamal this is always one byte less than the size of P on decryption, and twice the length as the size
        /// of P on encryption.
        /// </remarks>
        /// <returns>maximum size for an output block.</returns>
        public virtual int GetOutputBlockSize()
        {
            if (forEncryption)
                return 2 * ((bitSize + 7) / 8);

            return (bitSize - 1) / 8;
        }

        /// <summary>Process a single block using the basic ElGamal algorithm.</summary>
        /// <param name="input">the input array.</param>
        /// <param name="inOff">the offset into the input buffer where the data starts.</param>
        /// <param name="length">the length of the data to be processed.</param>
        /// <returns>the result of the ElGamal process.</returns>
        public virtual byte[] ProcessBlock(byte[] input, int inOff, int length)
        {
            if (key == null)
                throw new InvalidOperationException("ElGamal engine not initialised");

            int maxLength = forEncryption
                ? (bitSize - 1 + 7) / 8
                : GetInputBlockSize();

            BigInteger p = key.Parameters.P;

            if (key is ElGamalPrivateKeyParameters priv) // decryption
            {
                if (length != maxLength)
                    throw new DataLengthException("input is the wrong size for ElGamal cipher.");

                int halfLength = length / 2;
                BigInteger gamma = BigIntegers.FromUnsignedByteArray(input, inOff, halfLength);
                BigInteger phi = BigIntegers.FromUnsignedByteArray(input, inOff + halfLength, halfLength);

                // Both ciphertext components are peer-supplied, and gamma is raised below to the
                // (potentially static, reused) private-key-derived exponent, so both must be valid
                // public values in [2, p-2]. Otherwise a peer can submit a small-order or out-of-range
                // element to mount a small-subgroup confinement attack and, with a decryption oracle and
                // a reused key, recover the private key.
                BigInteger one = BigInteger.One;
                BigInteger pSub1 = p.Subtract(one);
                if ((gamma.CompareTo(one) <= 0 || gamma.CompareTo(pSub1) >= 0) ||
                    (phi.CompareTo(one) <= 0 || phi.CompareTo(pSub1) >= 0))
                {
                    throw new ArgumentException("ElGamal ciphertext element is weak");
                }

                // a shortcut, which generally relies on p being prime amongst other things.
                // if a problem with this shows up, check the p and g values!
                BigInteger m = gamma.ModPow(pSub1.Subtract(priv.X), p).ModMultiply(phi, p);

                return BigIntegers.AsUnsignedByteArray(m);
            }
            else if (key is ElGamalPublicKeyParameters pub) // encryption
            {
                if (length > maxLength)
                    throw new DataLengthException("input too large for ElGamal cipher.");

                BigInteger tmp = BigIntegers.FromUnsignedByteArray(input, inOff, length);

                if (tmp.CompareTo(p) >= 0)
                    throw new DataLengthException("input too large for ElGamal cipher.");

                BigInteger pSub2 = p.Subtract(BigInteger.Two);

                // TODO In theory, a series of 'k', 'g.ModPow(k, p)' and 'y.ModPow(k, p)' can be pre-calculated
                BigInteger k;
                do
                {
                    k = BigIntegers.CreateRandomBigInteger(p.BitLength, random);
                }
                while (k.SignValue == 0 || k.CompareTo(pSub2) > 0);

                BigInteger g = key.Parameters.G;
                BigInteger gamma = g.ModPow(k, p);
                BigInteger phi = pub.Y.ModPow(k, p).ModMultiply(tmp, p);

                int half = (bitSize + 7) / 8;
                byte[] output = new byte[2 * half];
                BigIntegers.AsUnsignedByteArray(gamma, output, 0, half);
                BigIntegers.AsUnsignedByteArray(phi, output, half, half);
                return output;
            }
            else
            {
                throw new InvalidOperationException();
            }
        }
    }
}
