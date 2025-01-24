using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
	/**
	* NaccacheStern Engine. For details on this cipher, please see
	* http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	*/
	public class NaccacheSternEngine
		: IAsymmetricBlockCipher
	{
		private bool forEncryption;

		private NaccacheSternKeyParameters key;

		private IList<BigInteger>[] lookup = null;

		public string AlgorithmName
		{
			get { return "NaccacheStern"; }
		}

		/**
		* Initializes this algorithm. Must be called before all other Functions.
		*
		* @see Org.BouncyCastle.Crypto.AsymmetricBlockCipher#init(bool,
		*      Org.BouncyCastle.Crypto.CipherParameters)
		*/
		public virtual void Init(bool forEncryption, ICipherParameters parameters)
		{
			this.forEncryption = forEncryption;

            parameters = ParameterUtilities.IgnoreRandom(parameters);

			key = (NaccacheSternKeyParameters)parameters;

			// construct lookup table for faster decryption if necessary
			if (!this.forEncryption)
			{
				NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
				var primes = priv.SmallPrimesList;
				lookup = new IList<BigInteger>[primes.Count];
				for (int i = 0; i < primes.Count; i++)
				{
					BigInteger actualPrime = primes[i];
					int actualPrimeValue = actualPrime.IntValue;

					lookup[i] = new List<BigInteger>(actualPrimeValue);
					lookup[i].Add(BigInteger.One);

					BigInteger accJ = BigInteger.Zero;
					for (int j = 1; j < actualPrimeValue; j++)
					{
						accJ = accJ.Add(priv.PhiN);
						BigInteger comp = accJ.Divide(actualPrime);
						lookup[i].Add(priv.G.ModPow(comp, priv.Modulus));
					}
				}
			}
		}

		/**
		* Returns the input block size of this algorithm.
		*
		* @see Org.BouncyCastle.Crypto.AsymmetricBlockCipher#GetInputBlockSize()
		*/
        public virtual int GetInputBlockSize()
		{
			if (forEncryption)
			{
				// We can only encrypt values up to lowerSigmaBound
				return (key.LowerSigmaBound + 7) / 8 - 1;
			}
			else
			{
				// We pad to modulus-size bytes for easier decryption.
//				return key.Modulus.ToByteArray().Length;
				return key.Modulus.BitLength / 8 + 1;
			}
		}

		/**
		* Returns the output block size of this algorithm.
		*
		* @see Org.BouncyCastle.Crypto.AsymmetricBlockCipher#GetOutputBlockSize()
		*/
        public virtual int GetOutputBlockSize()
		{
			if (forEncryption)
			{
				// encrypted Data is always padded up to modulus size
//				return key.Modulus.ToByteArray().Length;
				return key.Modulus.BitLength / 8 + 1;
			}
			else
			{
				// decrypted Data has upper limit lowerSigmaBound
				return (key.LowerSigmaBound + 7) / 8 - 1;
			}
		}

		/**
		* Process a single Block using the Naccache-Stern algorithm.
		*
		* @see Org.BouncyCastle.Crypto.AsymmetricBlockCipher#ProcessBlock(byte[],
		*      int, int)
		*/
        public virtual byte[] ProcessBlock(byte[] inBytes, int inOff, int length)
        {
            if (key == null)
                throw new InvalidOperationException("NaccacheStern engine not initialised");

            int inBlockSize = GetInputBlockSize();

            if (length > inBlockSize + 1)
                throw new DataLengthException("input too large for Naccache-Stern cipher.\n");

            if (!forEncryption)
            {
                // At decryption make sure that we receive padded data blocks
                if (length < inBlockSize)
                    throw new InvalidCipherTextException("BlockLength does not match modulus for Naccache-Stern cipher.\n");
            }

            // transform input into BigInteger
            BigInteger input = new BigInteger(1, inBytes, inOff, length);

            if (forEncryption)
                return Encrypt(input);

            var plain = new List<BigInteger>();
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
            var primes = priv.SmallPrimesList;
            // Get Chinese Remainders of CipherText
            for (int i = 0; i < primes.Count; i++)
            {
                BigInteger exp = input.ModPow(priv.PhiN.Divide(primes[i]), priv.Modulus);
                var al = lookup[i];
                if (lookup[i].Count != primes[i].IntValue)
                {
                    throw new InvalidCipherTextException("Error in lookup Array for "
                                    + primes[i].IntValue
                                    + ": Size mismatch. Expected ArrayList with length "
                                    + primes[i].IntValue + " but found ArrayList of length "
                                    + lookup[i].Count);
                }
                int lookedup = al.IndexOf(exp);

                if (lookedup == -1)
                    throw new InvalidCipherTextException("Lookup failed");

                plain.Add(BigInteger.ValueOf(lookedup));
            }
            BigInteger test = ChineseRemainder(plain, primes);

            // Should not be used as an oracle, so reencrypt output to see
            // if it corresponds to input

            // this breaks probabilisic encryption, so disable it. Anyway, we do
            // use the first n primes for key generation, so it is pretty easy
            // to guess them. But as stated in the paper, this is not a security
            // breach. So we can just work with the correct sigma.

            // if ((key.G.ModPow(test, key.Modulus)).Equals(input)) {
            //      output = test.ToByteArray();
            // } else {
            //      output = null;
            // }

            return test.ToByteArray();
        }

        /**
		* Encrypts a BigInteger aka Plaintext with the public key.
		*
		* @param plain
		*            The BigInteger to encrypt
		* @return The byte[] representation of the encrypted BigInteger (i.e.
		*         crypted.toByteArray())
		*/
        public virtual byte[] Encrypt(BigInteger plain)
        {
			// Always return modulus size values 0-padded at the beginning
			// 0-padding at the beginning is correctly parsed by BigInteger :)

			return BigIntegers.AsUnsignedByteArray(key.Modulus.BitLength / 8 + 1, key.G.ModPow(plain, key.Modulus));
        }

		/**
		* Adds the contents of two encrypted blocks mod sigma
		*
		* @param block1
		*            the first encrypted block
		* @param block2
		*            the second encrypted block
		* @return encrypt((block1 + block2) mod sigma)
		* @throws InvalidCipherTextException
		*/
        public virtual byte[] AddCryptedBlocks(byte[] block1, byte[] block2)
        {
			// check for correct blocksize
			int blockSize = forEncryption ? GetOutputBlockSize() : GetInputBlockSize();

            if (block1.Length > blockSize || block2.Length > blockSize)
                throw new InvalidCipherTextException("BlockLength too large for simple addition.\n");

            // calculate resulting block
            BigInteger m1Crypt = new BigInteger(1, block1);
            BigInteger m2Crypt = new BigInteger(1, block2);
            BigInteger m1m2Crypt = m1Crypt.Multiply(m2Crypt).Mod(key.Modulus);

            return BigIntegers.AsUnsignedByteArray(key.Modulus.BitLength / 8 + 1, m1m2Crypt);
        }

		/**
		* Convenience Method for data exchange with the cipher.
		*
		* Determines blocksize and splits data to blocksize.
		*
		* @param data the data to be processed
		* @return the data after it went through the NaccacheSternEngine.
		* @throws InvalidCipherTextException
		*/
        public virtual byte[] ProcessData(byte[] data)
		{
            int inBlockSize = GetInputBlockSize();

			if (data.Length <= inBlockSize)
                return ProcessBlock(data, 0, data.Length);

			int outBlockSize = GetOutputBlockSize();
			int datapos = 0;
			int retpos = 0;
			byte[] retval = new byte[(data.Length / inBlockSize + 1) * outBlockSize];
			while (datapos < data.Length)
			{
				byte[] tmp;
				if (datapos + inBlockSize < data.Length)
				{
					tmp = ProcessBlock(data, datapos, inBlockSize);
					datapos += inBlockSize;
				}
				else
				{
					tmp = ProcessBlock(data, datapos, data.Length - datapos);
					datapos += data.Length - datapos;
				}

				if (tmp == null)
                    throw new InvalidCipherTextException("cipher returned null");

                tmp.CopyTo(retval, retpos);
				retpos += tmp.Length;
			}

			if (retpos != retval.Length)
			{
				retval = Arrays.CopyOf(retval, retpos);
			}

			return retval;
		}

		/**
		* Computes the integer x that is expressed through the given primes and the
		* congruences with the chinese remainder theorem (CRT).
		*
		* @param congruences
		*            the congruences c_i
		* @param primes
		*            the primes p_i
		* @return an integer x for that x % p_i == c_i
		*/
		private static BigInteger ChineseRemainder(IList<BigInteger> congruences, IList<BigInteger> primes)
		{
			BigInteger retval = BigInteger.Zero;
			BigInteger all = BigInteger.One;
			for (int i = 0; i < primes.Count; i++)
			{
				all = all.Multiply(primes[i]);
			}
			for (int i = 0; i < primes.Count; i++)
			{
				BigInteger a = primes[i];
				BigInteger b = all.Divide(a);
				BigInteger b2 = b.ModInverse(a);
				BigInteger tmp = b.Multiply(b2);
				tmp = tmp.Multiply(congruences[i]);
				retval = retval.Add(tmp);
			}

			return retval.Mod(all);
		}
	}
}
