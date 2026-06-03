using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    internal class DHParametersHelper
    {
        private static readonly BigInteger Two = BigInteger.Two;
        private static readonly BigInteger Twelve = BigInteger.ValueOf(12);
        private static readonly BigInteger TwentyFour = BigInteger.ValueOf(24);

        private static readonly int[][] primeLists = BigInteger.primeLists;
        private static readonly int[] primeProducts = BigInteger.primeProducts;
        private static readonly BigInteger[] BigPrimeProducts = Array.ConvertAll(primeProducts, BigInteger.ValueOf);

        /// <summary>Finds a pair of prime BigInteger's {p, q: p = 2q + 1}.</summary>
        /// <remarks>
        /// See: Handbook of Applied Cryptography 4.86. If forGenerator2 is true, the returned p will also have 2 as a
        /// quadratic residue.
        /// </remarks>
        internal static BigInteger[] GenerateSafePrimes(int bitLength, int certainty, SecureRandom random,
            bool forGenerator2)
        {
            if (bitLength < 64)
                throw new ArgumentException("size < 64");

            int lowBitsSet = 0x03;
            int inc3 = 4;
            BigInteger step = Twelve;

            if (forGenerator2)
            {
                // When selecting p,q so that g == 2 will generate the order q subgroup, we want p === 7 mod 8
                lowBitsSet = 0x07;
                inc3 = -8;
                step = TwentyFour;
            }

            int minWeight = bitLength >> 2;
            int byteLength = (bitLength + 7) / 8;
            int extraBits = byteLength * 8 - bitLength;

            byte[] bytes = new byte[byteLength];

            for (;;)
            {
                random.NextBytes(bytes);

                // strip off excess bits, set MSB and LSB
                bytes[0] = (byte)((bytes[0] & (0xFF >> extraBits)) | (0x80 >> extraBits));
                bytes[bytes.Length - 1] |= (byte)lowBitsSet;

                BigInteger p = new BigInteger(1, bytes);

                // Check p mod 3
                int pMod3 = p.Mod(BigInteger.Three).IntValueExact;
                if (pMod3 != 2)
                {
                    // Result will be p === 11 mod 12 (forGenerator2 => p === 23 mod 24)
                    p = p.Add(BigInteger.ValueOf((2 - pMod3) * inc3));
                }

                int count = 0;
                while (++count <= 256 && p.BitLength == bitLength)
                {
                    // Check for small factors in p and q simultaneously
                    if (!HasAnySmallFactorsSafe(p))
                    {
                        // NOTE: Pocklington criterion: Fermat test suffices to prove p prime given q is prime
                        if (Two.ModPow(p, p).Equals(Two))
                        {
                            BigInteger q = p.ShiftRight(1);
                            if (q.RabinMillerTest(certainty, random, randomlySelected: true))
                            {
                                /*
                                 * Require a minimum weight of the NAF representation, since low-weight primes may
                                 * be weak against a version of the number-field-sieve for the
                                 * discrete-logarithm-problem.
                                 * 
                                 * See "The number field sieve for integers of low weight", Oliver Schirokauer.
                                 */
                                if (WNafUtilities.GetNafWeight(p) >= minWeight)
                                    return new BigInteger[]{ p, q };
                            }
                        }

                        // Start from a new random value
                        break;
                    }

                    p = p.Add(step);
                }
            }
        }

        private static bool HasAnySmallFactorsSafe(BigInteger x)
        {
            for (int i = 0; i < primeLists.Length; ++i)
            {
                int r = x.Remainder(BigPrimeProducts[i]).IntValueExact;

                foreach (int prime in primeLists[i])
                {
                    if ((r % prime) < 2)
                        return true;
                }
            }

            return false;
        }

#if false
        /*
         * Select a high order element of the multiplicative group Zp*
         * 
         * p and q must be s.t. p = 2*q + 1, where p and q are prime (see generateSafePrimes)
         */
        internal static BigInteger SelectGenerator(BigInteger p, BigInteger q, SecureRandom random)
        {
            BigInteger pMinusTwo = p.Subtract(BigInteger.Two);
            BigInteger g;

            /*
             * (see: Handbook of Applied Cryptography 4.80)
             */
            //do
            //{
            //    g = BigIntegers.CreateRandomInRange(BigInteger.Two, pMinusTwo, random);
            //}
            //while (g.ModPow(BigInteger.Two, p).Equals(BigInteger.One) ||
            //       g.ModPow(q, p).Equals(BigInteger.One));

            /*
             * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
             */
            do
            {
                BigInteger h = BigIntegers.CreateRandomInRange(BigInteger.Two, pMinusTwo, random);

                g = h.Square().Mod(p);
            }
            while (g.Equals(BigInteger.One));

            return g;
        }
#endif
    }
}
