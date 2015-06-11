using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math
{
    public static class Primes
    {
        private static readonly BigInteger One = BigInteger.One;
        private static readonly BigInteger Two = BigInteger.Two;
        private static readonly BigInteger Three = BigInteger.Three;

        /**
         * Used to return the output from the {@linkplain #generateSTRandomPrime(Digest) Shawe-Taylor Random_Prime Routine} 
         */
        public class STOutput
        {
            private readonly BigInteger mPrime;
            private readonly byte[] mPrimeSeed;
            private readonly int mPrimeGenCounter;

            internal STOutput(BigInteger prime, byte[] primeSeed, int primeGenCounter)
            {
                this.mPrime = prime;
                this.mPrimeSeed = primeSeed;
                this.mPrimeGenCounter = primeGenCounter;
            }

            public BigInteger Prime
            {
                get { return mPrime; }
            }

            public byte[] PrimeSeed
            {
                get { return mPrimeSeed; }
            }

            public int PrimeGenCounter
            {
                get { return mPrimeGenCounter; }
            }
        }

        /**
         * FIPS 186-4 C.6 Shawe-Taylor Random_Prime Routine
         * 
         * Construct a provable prime number using a hash function.
         * 
         * @param hash
         *            the {@link Digest} instance to use (as "Hash()"). Cannot be null.
         * @param length
         *            the length (in bits) of the prime to be generated. Must be >= 2.
         * @param inputSeed
         *            the seed to be used for the generation of the requested prime. Cannot be null or
         *            empty.
         * @returns an {@link STOutput} instance containing the requested prime.
         */
        public static STOutput GenerateSTRandomPrime(IDigest hash, int length, byte[] inputSeed)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (length < 2)
                throw new ArgumentException("must be >= 2", "length");
            if (inputSeed == null)
                throw new ArgumentNullException("inputSeed");
            if (inputSeed.Length == 0)
                throw new ArgumentException("cannot be empty", "inputSeed");

            return ImplSTRandomPrime(hash, length, Arrays.Clone(inputSeed));
        }

        private static STOutput ImplSTRandomPrime(IDigest d, int length, byte[] primeSeed)
        {
            int dLen = d.GetDigestSize();

            if (length < 33)
            {
                int primeGenCounter = 0;

                byte[] c0 = new byte[dLen];
                byte[] c1 = new byte[dLen];

                for (;;)
                {
                    Hash(d, primeSeed, c0, 0);
                    Inc(primeSeed, 1);

                    Hash(d, primeSeed, c1, 0);
                    Inc(primeSeed, 1);

                    uint c = Extract32(c0) ^ Extract32(c1);
                    c &= (uint.MaxValue >> (32 - length));
                    c |= (1U << (length - 1)) | 1U;

                    ++primeGenCounter;

                    if (IsPrime32(c))
                    {
                        return new STOutput(BigInteger.ValueOf((long)c), primeSeed, primeGenCounter);
                    }

                    if (primeGenCounter > (4 * length))
                    {
                        throw new InvalidOperationException("Too many iterations in Shawe-Taylor Random_Prime Routine");
                    }
                }
            }

            STOutput rec = ImplSTRandomPrime(d, (length + 3)/2, primeSeed);

            {
                BigInteger c0 = rec.Prime;
                primeSeed = rec.PrimeSeed;
                int primeGenCounter = rec.PrimeGenCounter;

                int outlen = 8 * dLen;
                int iterations = (length - 1)/outlen;

                int oldCounter = primeGenCounter;

                BigInteger x = HashGen(d, primeSeed, iterations + 1);
                x = x.Mod(One.ShiftLeft(length - 1)).SetBit(length - 1);

                BigInteger c0x2 = c0.ShiftLeft(1);
                BigInteger t = x.Subtract(One).Divide(c0x2).Add(One);

                BigInteger c = t.Multiply(c0x2).Add(One);

                for (;;)
                {
                    if (c.BitLength > length)
                    {
                        t = One.ShiftLeft(length - 1).Subtract(One).Divide(c0x2).Add(One);
                        c = t.Multiply(c0x2).Add(One);
                    }

                    ++primeGenCounter;

                    /*
                     * This is an optimization of the original algorithm, using trial division to screen out
                     * many non-primes quickly.
                     * 
                     * NOTE: 'primeSeed' is still incremented as if we performed the full check!
                     */
                    if (MightBePrime(c))
                    {
                        BigInteger a = HashGen(d, primeSeed, iterations + 1);
                        a = a.Mod(c.Subtract(Three)).Add(Two);

                        BigInteger z = a.ModPow(t.ShiftLeft(1), c);

                        if (c.Gcd(z.Subtract(One)).Equals(One) && z.ModPow(c0, c).Equals(One))
                        {
                            return new STOutput(c, primeSeed, primeGenCounter);
                        }
                    }
                    else
                    {
                        Inc(primeSeed, iterations + 1);
                    }

                    if (primeGenCounter >= ((4 * length) + oldCounter))
                    {
                        throw new InvalidOperationException("Too many iterations in Shawe-Taylor Random_Prime Routine");
                    }

                    t = t.Add(One);
                    c = c.Add(c0x2);
                }
            }
        }

        private static uint Extract32(byte[] bs)
        {
            uint result = 0;

            int count = System.Math.Min(4, bs.Length);
            for (int i = 0; i < count; ++i)
            {
                uint b = bs[bs.Length - (i + 1)];
                result |= (b << (8 * i));
            }

            return result;
        }

        private static void Hash(IDigest d, byte[] input, byte[] output, int outPos)
        {
            d.BlockUpdate(input, 0, input.Length);
            d.DoFinal(output, outPos);
        }

        private static BigInteger HashGen(IDigest d, byte[] seed, int count)
        {
            int dLen = d.GetDigestSize();
            int pos = count * dLen;
            byte[] buf = new byte[pos];
            for (int i = 0; i < count; ++i)
            {
                pos -= dLen;
                Hash(d, seed, buf, pos);
                Inc(seed, 1);
            }
            return new BigInteger(1, buf);
        }

        private static void Inc(byte[] seed, int c)
        {
            int pos = seed.Length;
            while (c > 0 && --pos >= 0)
            {
                c += seed[pos];
                seed[pos] = (byte)c;
                c >>= 8;
            }
        }

        private static bool IsPrime32(uint x)
        {
            /*
             * Use wheel factorization with 2, 3, 5 to select trial divisors.
             */

            if (x <= 5)
            {
                return x == 2 || x == 3 || x == 5;
            }

            if ((x & 1) == 0 || (x % 3) == 0 || (x % 5) == 0)
            {
                return false;
            }

            uint[] ds = new uint[]{ 1, 7, 11, 13, 17, 19, 23, 29 };
            uint b = 0;
            for (int pos = 1; ; pos = 0)
            {
                /*
                 * Trial division by wheel-selected divisors
                 */
                while (pos < ds.Length)
                {
                    uint d = b + ds[pos];
                    if (x % d == 0)
                    {
                        return x < 30;
                    }
                    ++pos;
                }

                b += 30;

                if ((b >> 16 != 0) || (b * b >= x))
                {
                    return true;
                }
            }
        }

        private static bool MightBePrime(BigInteger x)
        {
            /*
             * Bundle trial divisors into ~32-bit moduli then use fast tests on the ~32-bit remainders.
             */
            int m0 = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23;
            int r0 = x.Mod(BigInteger.ValueOf(m0)).IntValue;
            if ((r0 & 1) != 0 && (r0 % 3) != 0 && (r0 % 5) != 0 && (r0 % 7) != 0 && (r0 % 11) != 0
                && (r0 % 13) != 0 && (r0 % 17) != 0 && (r0 % 19) != 0 && (r0 % 23) != 0)
            {
                int m1 = 29 * 31 * 37 * 41 * 43;
                int r1 = x.Mod(BigInteger.ValueOf(m1)).IntValue;
                if ((r1 % 29) != 0 && (r1 % 31) != 0 && (r1 % 37) != 0 && (r1 % 41) != 0 && (r1 % 43) != 0)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
