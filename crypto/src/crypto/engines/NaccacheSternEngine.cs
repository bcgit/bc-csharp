using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.Raw;
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

        // one fixed-length encoding per possible digit, per small prime, so the search in decryption can compare
        // byte by byte without the length itself saying anything
        private byte[][][] lookup = null;

        private int modulusLength;

        // CRT recombination data, derived only from the small primes: for each prime p_i, sigma / p_i (at the
        // accumulator length) and its inverse mod p_i; and sigma * 2^j for the final reduction
        private uint[][] crtCofactors;
        private uint[] crtInverses;
        private uint[][] crtSigmaMultiples;

        private SecureRandom random;

        /// <inheritdoc/>
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

            parameters = ParameterUtilities.GetRandom(parameters, out var providedRandom);

            key = (NaccacheSternKeyParameters)parameters;

            // construct lookup table for faster decryption if necessary
            if (!this.forEncryption)
            {
                // decryption blinds its private exponents
                random = CryptoServicesRegistrar.GetSecureRandom(providedRandom);

                NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
                modulusLength = (priv.Modulus.BitLength + 7) / 8;
                var primes = priv.SmallPrimesList;
                lookup = new byte[primes.Count][][];
                for (int i = 0; i < primes.Count; i++)
                {
                    BigInteger actualPrime = primes[i];
                    int actualPrimeValue = actualPrime.IntValue;

                    lookup[i] = new byte[actualPrimeValue][];
                    lookup[i][0] = BigIntegers.AsUnsignedByteArray(modulusLength, BigInteger.One);

                    // entry j is g^(j * phi(n) / p) = h^j for h = g^(phi(n) / p), so one exponentiation and then
                    // repeated multiplication build the table. The exponent carries phi(n), the private key, so it is
                    // blinded with a random multiple of phi(n) before the variable-time ModPow; g is coprime to n, so h
                    // is unchanged. The entries are as sensitive as the key (h - 1 shares a prime factor with n), so
                    // the chain uses the fixed-time ModMult rather than ModMultiply, whose reduction follows the value.
                    BigInteger exponent = BigIntegers.CreateBlindedExponent(PhiNOverSmallPrime(priv, actualPrime),
                        priv.PhiN, random);
                    BigInteger h = priv.G.ModPow(exponent, priv.Modulus);
                    BigInteger entry = BigInteger.One;
                    for (int j = 1; j < actualPrimeValue; j++)
                    {
                        entry = BigIntegers.ModMult(priv.Modulus, entry, h);
                        lookup[i][j] = BigIntegers.AsUnsignedByteArray(modulusLength, entry);
                    }
                }

                // sum_i d_i * (sigma / p_i) * ((sigma / p_i)^-1 mod p_i) is below count * sigma, so bitlength(count)
                // masked subtractions of sigma * 2^j reduce it mod sigma; the accumulator is sized for that sum
                BigInteger sigma = BigInteger.One;
                for (int i = 0; i < primes.Count; i++)
                {
                    sigma = sigma.Multiply(primes[i]);
                }

                int reductions = Integers.BitLength(primes.Count);
                int crtBits = sigma.BitLength + reductions;

                crtCofactors = new uint[primes.Count][];
                crtInverses = new uint[primes.Count];
                for (int i = 0; i < primes.Count; i++)
                {
                    BigInteger cofactor = sigma.Divide(primes[i]);
                    crtCofactors[i] = Nat.FromBigInteger(crtBits, cofactor);
                    crtInverses[i] = (uint)cofactor.ModInverse(primes[i]).IntValue;
                }

                crtSigmaMultiples = new uint[reductions][];
                for (int j = 0; j < reductions; j++)
                {
                    crtSigmaMultiples[j] = Nat.FromBigInteger(crtBits, sigma.ShiftLeft(j));
                }
            }
            else
            {
                random = null;
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
// return key.Modulus.ToByteArray().Length;
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
// return key.Modulus.ToByteArray().Length;
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

            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
            var primes = priv.SmallPrimesList;

            // The plaintext is recombined from its digits d_i = plaintext mod p_i by the CRT, in a fixed-length
            // accumulator so that neither the digits nor the sum steer the work (BigInteger arithmetic shortcuts zero
            // operands, sizes products by their values, and reduces by shift-and-subtract over the quotient).
            int crtLength = crtCofactors[0].Length;
            uint[] acc = Nat.Create(crtLength);
            uint[] tmp = Nat.Create(crtLength);
            try
            {
                for (int i = 0; i < primes.Count; i++)
                {
                    // input is the caller's ciphertext and the exponent is derived from phi(n), which is the private
                    // key, so the exponent is blinded before the variable-time ModPow. input^phi(n) = 1 (mod n) for any
                    // input coprime to n, so the result is unchanged; an input sharing a factor with n fails the
                    // lookup either way.
                    BigInteger exponent = BigIntegers.CreateBlindedExponent(PhiNOverSmallPrime(priv, primes[i]),
                        priv.PhiN, random);
                    BigInteger exp = input.ModPow(exponent, priv.Modulus);
                    byte[][] al = lookup[i];
                    if (al.Length != primes[i].IntValue)
                    {
                        throw new InvalidCipherTextException("Error in lookup Array for "
                                        + primes[i].IntValue
                                        + ": Size mismatch. Expected ArrayList with length "
                                        + primes[i].IntValue + " but found ArrayList of length "
                                        + al.Length);
                    }

                    // the CRT term d_i * (sigma / p_i) * ((sigma / p_i)^-1 mod p_i) mod sigma is (sigma / p_i) * t_i
                    // for t_i = d_i * (sigma / p_i)^-1 mod p_i, and the lookup yields t_i directly, so each term is
                    // below sigma and needs no reduction of its own
                    if (!FixedTimeLookup(al, BigIntegers.AsUnsignedByteArray(modulusLength, exp), crtInverses[i],
                        out uint t))
                    {
                        throw new InvalidCipherTextException("Lookup failed");
                    }

                    Nat.MulWordAddTo(crtLength, t, crtCofactors[i], 0, acc, 0);
                }

                // acc < count * sigma <= 2^reductions * sigma, and each masked subtraction of sigma * 2^j halves the
                // bound, leaving acc < sigma
                for (int j = crtSigmaMultiples.Length - 1; j >= 0; --j)
                {
                    int borrow = Nat.Sub(crtLength, acc, crtSigmaMultiples[j], tmp);
                    Nat.CMov(crtLength, ~borrow, tmp, 0, acc, 0);
                }

                // No check that g^test re-encrypts to the input: a valid ciphertext need not equal g^test, since
                // probabilistic encryption multiplies in x^sigma and AddCryptedBlocks can leave a sum beyond sigma
                BigInteger test = Nat.ToBigInteger(crtLength, acc);
                return test.ToByteArray();
            }
            finally
            {
                Arrays.ZeroMemory(acc);
                Arrays.ZeroMemory(tmp);
            }
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

        // phi(n) / p for one of the key's small primes, without BigInteger.Divide, whose shift-and-subtract loop follows
        // the bits of the quotient. p divides sigma, which divides phi(n), so the division is exact and the quotient is
        // below 2^k for k the modulus bit length; it is therefore phi(n) * p^-1 mod 2^k, one multiplication and a mask.
        // Only correct when p divides phi(n), hence kept local to this engine.
        // TODO Consider word-level exact division (one pass using p^-1 mod 2^32) instead of the full multiply; currently
        // negligible next to the ModPow each result feeds.
        private static BigInteger PhiNOverSmallPrime(NaccacheSternPrivateKeyParameters priv, BigInteger p)
        {
            BigInteger m = BigInteger.One.ShiftLeft(priv.Modulus.BitLength);
            BigInteger q = priv.PhiN.Multiply(p.ModInverse(m)).Mod(m);

            Debug.Assert(q.Multiply(p).Equals(priv.PhiN));

            return q;
        }

        // The index of the match is the plaintext digit d for this prime (the table length p), so returning as soon as
        // it is found (as List.IndexOf did) made the running time reveal it. Scan the whole table and select by mask.
        // The CRT needs d only as d * inv mod p, so that is what is selected, from a running j * inv mod p.
        private static bool FixedTimeLookup(byte[][] table, byte[] value, uint inv, out uint digitTimesInv)
        {
            uint p = (uint)table.Length;
            Debug.Assert(p <= int.MaxValue && inv < p);

            int found = 0;                                  // -1 once something has matched
            uint r = 0;                                     // j * inv mod p
            uint result = 0;

            for (int j = 0; j < table.Length; ++j)
            {
                byte[] candidate = table[j];
                int diff = 0;

                for (int k = 0; k < value.Length; ++k)
                {
                    diff |= candidate[k] ^ value[k];
                }

                int isEqual = (diff - 1) >> 31;             // -1 when equal, 0 otherwise

                result |= r & (uint)(isEqual & ~found);
                found |= isEqual;

                // r + inv < 2p, and with p below 2^31 the difference r + inv - p is in (-2^31, 2^31)
                uint s = r + inv;
                uint below = (uint)((int)(s - p) >> 31);    // all ones when s < p
                r = s - (p & ~below);
            }

            digitTimesInv = result;
            return found != 0;
        }
    }
}
