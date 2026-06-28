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

            if (length > maxLength)
                throw new DataLengthException("input too large for ElGamal cipher.\n");

            BigInteger p = key.Parameters.P;

            byte[] output;
            if (key is ElGamalPrivateKeyParameters priv) // decryption
            {
                int halfLength = length / 2;
                BigInteger gamma = new BigInteger(1, input, inOff, halfLength);
                BigInteger phi = new BigInteger(1, input, inOff + halfLength, halfLength);

                // a shortcut, which generally relies on p being prime amongst other things.
                // if a problem with this shows up, check the p and g values!
                BigInteger m = gamma.ModPow(p.Subtract(BigInteger.One).Subtract(priv.X), p).Multiply(phi).Mod(p);

                output = m.ToByteArrayUnsigned();
            }
            else if (key is ElGamalPublicKeyParameters pub) // encryption
            {
                BigInteger tmp = new BigInteger(1, input, inOff, length);

                if (tmp.BitLength >= p.BitLength)
                    throw new DataLengthException("input too large for ElGamal cipher.\n");

                BigInteger pSub2 = p.Subtract(BigInteger.Two);

                // TODO In theory, a series of 'k', 'g.ModPow(k, p)' and 'y.ModPow(k, p)' can be pre-calculated
                BigInteger k;
                do
                {
                    k = new BigInteger(p.BitLength, random);
                }
                while (k.SignValue == 0 || k.CompareTo(pSub2) > 0);

                BigInteger g = key.Parameters.G;
                BigInteger gamma = g.ModPow(k, p);
                BigInteger phi = tmp.Multiply(pub.Y.ModPow(k, p)).Mod(p);

                output = new byte[this.GetOutputBlockSize()];

                int mid = output.Length / 2;
                BigIntegers.AsUnsignedByteArray(gamma, output, 0, mid);
                BigIntegers.AsUnsignedByteArray(phi, output, mid, output.Length - mid);
            }
            else
            {
                throw new InvalidOperationException();
            }

            return output;
        }
    }
}
