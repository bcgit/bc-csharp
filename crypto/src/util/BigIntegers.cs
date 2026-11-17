using System;
using System.IO;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Utilities
{
    /**
     * BigInteger utilities.
     */
    public static class BigIntegers
    {
        /// <summary>The value zero.</summary>
        public static readonly BigInteger Zero = BigInteger.Zero;
        /// <summary>The value one.</summary>
        public static readonly BigInteger One = BigInteger.One;

        private const int MaxIterations = 1000;

        // Hexadecimal value of the product of the 131 smallest odd primes from 3 to 743
        private static readonly BigInteger SmallPrimesProduct = new BigInteger(
             "8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f"
            + "73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2"
            + "ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8"
            + "f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f",
            16);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Write the magnitude of a non-negative BigInteger into a span of 32-bit words, least significant word first.
        /// </summary>
        /// <param name="n">The value to convert.</param>
        /// <param name="buf">The span to receive the words; unused high words are set to zero.</param>
        /// <exception cref="ArgumentException">
        /// The value is negative or does not fit in <paramref name="buf"/>.
        /// </exception>
        [CLSCompliant(false)]
        public static void AsUint32ArrayLittleEndian(BigInteger n, Span<uint> buf)
        {
            int uintsLength = n.GetLengthofUInt32Array();

            if (uintsLength > buf.Length)
                throw new ArgumentException("standard length exceeded", nameof(n));

            n.ToUInt32ArrayLittleEndian(buf);

            int sign = (int)buf[uintsLength - 1] >> 31;
            buf[uintsLength..].Fill((uint)sign);
        }
#endif

        /**
        * Return the passed in value as an unsigned byte array.
        *
        * @param value the value to be converted.
        * @return a byte array without a leading zero byte if present in the signed encoding.
        */
        public static byte[] AsUnsignedByteArray(BigInteger n)
        {
            return n.ToByteArrayUnsigned();
        }

        /**
         * Return the passed in value as an unsigned byte array of the specified length, padded with
         * leading zeros as necessary.
         * @param length the fixed length of the result.
         * @param n the value to be converted.
         * @return a byte array padded to a fixed length with leading zeros.
         */
        public static byte[] AsUnsignedByteArray(int length, BigInteger n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int bytesLength = n.GetLengthofByteArrayUnsigned();

            if (bytesLength > length)
                throw new ArgumentException("standard length exceeded", nameof(n));

            byte[] bytes = new byte[length];
            n.ToByteArrayUnsigned(bytes.AsSpan(length - bytesLength));
            return bytes;
#else
            byte[] bytes = n.ToByteArrayUnsigned();
            int bytesLength = bytes.Length;

            if (bytesLength == length)
                return bytes;

            if (bytesLength > length)
                throw new ArgumentException("standard length exceeded", nameof(n));

            byte[] tmp = new byte[length];
            Array.Copy(bytes, 0, tmp, length - bytesLength, bytesLength);
            return tmp;
#endif
        }

        /**
         * Write the passed in value as unsigned bytes to the specified buffer range, padded with
         * leading zeros as necessary.
         *
         * @param n
         *            the value to be converted.
         * @param buf
         *            the buffer to which the value is written.
         * @param off
         *            the start offset in array <code>buf</code> at which the data is written.
         * @param len
         *            the fixed length of data written (possibly padded with leading zeros).
         */
        public static void AsUnsignedByteArray(BigInteger n, byte[] buf, int off, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            AsUnsignedByteArray(n, buf.AsSpan(off, len));
#else
            byte[] bytes = n.ToByteArrayUnsigned();
            int bytesLength = bytes.Length;

            if (bytesLength > len)
                throw new ArgumentException("standard length exceeded", nameof(n));

            int padLen = len - bytesLength;
            Arrays.Fill(buf, off, off + padLen, 0);
            Array.Copy(bytes, 0, buf, off + padLen, bytesLength);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Write the magnitude of a non-negative BigInteger into a span as a big-endian unsigned value, left-padded
        /// with zeros.
        /// </summary>
        /// <param name="n">The value to convert.</param>
        /// <param name="buf">The span to receive the bytes; its length determines the size of the encoding.</param>
        /// <exception cref="ArgumentException">
        /// The value is negative or does not fit in <paramref name="buf"/>.
        /// </exception>
        public static void AsUnsignedByteArray(BigInteger n, Span<byte> buf)
        {
            int bytesLength = n.GetLengthofByteArrayUnsigned();

            if (bytesLength > buf.Length)
                throw new ArgumentException("standard length exceeded", nameof(n));

            buf[..^bytesLength].Fill(0x00);
            n.ToByteArrayUnsigned(buf[^bytesLength..]);
        }
#endif

        internal static BigInteger CreateBlindedExponent(BigInteger exponent, BigInteger groupOrder,
            SecureRandom random)
        {
            int randomBits = 7;
            BigInteger blind = CreateRandomBigInteger(randomBits, random).SetBit(randomBits);
            return exponent.Add(blind.Multiply(groupOrder));
        }

        /// <summary>
        /// Creates a Random BigInteger from the secure random of a given bit length.
        /// </summary>
        /// <param name="bitLength"></param>
        /// <param name="secureRandom"></param>
        /// <returns></returns>
        public static BigInteger CreateRandomBigInteger(int bitLength, SecureRandom secureRandom) =>
            new BigInteger(bitLength, secureRandom);

        /**
        * Return a random BigInteger not less than 'min' and not greater than 'max'
        *
        * @param min the least value that may be generated
        * @param max the greatest value that may be generated
        * @param random the source of randomness
        * @return a random BigInteger value in the range [min,max]
        */
        public static BigInteger CreateRandomInRange(BigInteger min, BigInteger max, SecureRandom random)
        {
            int cmp = min.CompareTo(max);
            if (cmp >= 0)
            {
                if (cmp > 0)
                    throw new ArgumentException("'min' may not be greater than 'max'");

                return min;
            }

            if (min.BitLength > max.BitLength / 2)
                return CreateRandomInRange(BigInteger.Zero, max.Subtract(min), random).Add(min);

            for (int i = 0; i < MaxIterations; ++i)
            {
                BigInteger x = new BigInteger(max.BitLength, random);
                if (x.CompareTo(min) >= 0 && x.CompareTo(max) <= 0)
                    return x;
            }

            // fall back to a faster (restricted) method
            return new BigInteger(max.Subtract(min).BitLength - 1, random).Add(min);
        }

        /// <summary>Generate a random prime number of a given bit length.</summary>
        /// <param name="bitLength">The bit length of the prime.</param>
        /// <param name="certainty">
        /// A measure of the uncertainty that the caller is willing to tolerate that the number is prime.
        /// </param>
        /// <param name="random">The source of randomness.</param>
        /// <returns>A probable prime of the requested bit length.</returns>
        public static BigInteger CreateRandomPrime(int bitLength, int certainty, SecureRandom random) =>
            new BigInteger(bitLength, certainty, random);

        /// <summary>
        /// Create a non-negative BigInteger from a big-endian unsigned byte array (or a segment of one).
        /// </summary>
        /// <param name="buf">The buffer holding the value.</param>
        /// <returns>The non-negative value represented by the bytes.</returns>
        public static BigInteger FromUnsignedByteArray(byte[] buf)
        {
            return new BigInteger(1, buf);
        }

        /// <summary>
        /// Create a non-negative BigInteger from a big-endian unsigned byte array (or a segment of one).
        /// </summary>
        /// <param name="buf">The buffer holding the value.</param>
        /// <param name="off">The offset into <paramref name="buf"/> at which the value starts.</param>
        /// <param name="length">The number of bytes in the value.</param>
        /// <returns>The non-negative value represented by the bytes.</returns>
        public static BigInteger FromUnsignedByteArray(byte[] buf, int off, int length)
        {
            return new BigInteger(1, buf, off, length);
        }

        /// <summary>
        /// Get the length in bytes of the two's complement encoding of a value, including a sign bit.
        /// </summary>
        /// <param name="n">The value.</param>
        /// <returns>The number of bytes required.</returns>
        public static int GetByteLength(BigInteger n)
        {
            return n.GetLengthofByteArray();
        }

        /// <summary>Get the length in bytes of the unsigned encoding of a value.</summary>
        /// <param name="n">The value.</param>
        /// <returns>The number of bytes required to hold the magnitude of the value.</returns>
        public static int GetUnsignedByteLength(BigInteger n)
        {
            return n.GetLengthofByteArrayUnsigned();
        }

        /// <summary>Determine whether a value is even or has a small odd prime factor (up to 743).</summary>
        /// <param name="x">The value to test.</param>
        /// <returns>true if a small factor was found, false otherwise.</returns>
        public static bool HasAnySmallFactors(BigInteger x)
        {
            if (!x.TestBit(0))
                return true;

            BigInteger y = SmallPrimesProduct;
            if (x.BitLength < SmallPrimesProduct.BitLength)
            {
                y = x;
                x = SmallPrimesProduct;
            }

            return !ModOddIsCoprimeVar(x, y);
        }

        /// <summary>(X + Y) mod M, for X and Y already in [0, M), in time independent of the values.</summary>
        /// <remarks>
        /// Use this rather than <c>X.Add(Y).Mod(M)</c> when either operand is secret: a reduction short-circuits when
        /// its input is already below the modulus, so whether the sum crossed M would be visible. Operands outside
        /// [0, M) are rejected rather than reduced, since reducing them is the variable-time step this avoids.
        /// </remarks>
        internal static BigInteger ModAdd(BigInteger M, BigInteger X, BigInteger Y)
        {
            CheckModOperands(M, X, Y);

            // the extra bit of width means X + Y, below 2M, cannot carry out of the top word, so one conditional
            // subtraction of M reduces it
            int bits = M.BitLength + 1;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (bits <= 2049)
            {
                int len = Nat.GetLengthForBits(bits);
                Span<uint> m = stackalloc uint[len];
                Span<uint> x = stackalloc uint[len];
                Span<uint> y = stackalloc uint[len];
                Nat.FromBigInteger(bits, M, m);
                Nat.FromBigInteger(bits, X, x);
                Nat.FromBigInteger(bits, Y, y);

                Nat.Add(len, x, y, x);
                int borrow = Nat.Sub(len, x, m, y);     // y = x - M; borrow is -1 exactly when x < M
                Nat.CMov(len, ~borrow, y, x);           // keep x - M unless the subtraction went negative
                return Nat.ToBigInteger(len, x);
            }
            else
#endif
            {
                uint[] m = Nat.FromBigInteger(bits, M);
                uint[] x = Nat.FromBigInteger(bits, X);
                uint[] y = Nat.FromBigInteger(bits, Y);
                int len = m.Length;

                Nat.Add(len, x, y, x);
                int borrow = Nat.Sub(len, x, m, y);     // y = x - M; borrow is -1 exactly when x < M
                Nat.CMov(len, ~borrow, y, 0, x, 0);     // keep x - M unless the subtraction went negative
                return Nat.ToBigInteger(len, x);
            }
        }

        /// <summary>(X * Y) mod M, for odd M and X, Y already in [0, M), in time independent of the values.</summary>
        /// <remarks>
        /// Montgomery multiplication over a fixed number of words. Use this rather than <c>X.Multiply(Y).Mod(M)</c> when
        /// either operand is secret: that reduction is a real division whose work follows the quotient. Operands outside
        /// [0, M) are rejected rather than reduced.
        /// </remarks>
        internal static BigInteger ModMult(BigInteger M, BigInteger X, BigInteger Y)
        {
            if (!M.TestBit(0))
                throw new ArgumentException("must be odd", nameof(M));

            CheckModOperands(M, X, Y);

            int bits = M.BitLength;
            int len = Nat.GetLengthForBits(bits);

            // R = 2^(32 * len) exceeds the odd M, so they are coprime. R^2 mod M depends only on the public modulus.
            BigInteger R2 = One.ShiftLeft(len << 6).Mod(M);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (bits <= 2048)
            {
                Span<uint> m = stackalloc uint[len];
                Span<uint> x = stackalloc uint[len];
                Span<uint> y = stackalloc uint[len];
                Span<uint> r2 = stackalloc uint[len];
                Span<uint> t = stackalloc uint[2 * len + 1];
                Nat.FromBigInteger(bits, M, m);
                Nat.FromBigInteger(bits, X, x);
                Nat.FromBigInteger(bits, Y, y);
                Nat.FromBigInteger(bits, R2, r2);
                uint mDash = 0U - Mod.Inverse32(m[0]);

                // the first product leaves X * Y * R^-1, the second multiplies by R^2 * R^-1 to undo it
                MontgomeryMultiply(len, x, y, m, mDash, t, x);
                MontgomeryMultiply(len, x, r2, m, mDash, t, x);
                return Nat.ToBigInteger(len, x);
            }
            else
#endif
            {
                uint[] m = Nat.FromBigInteger(bits, M);
                uint[] x = Nat.FromBigInteger(bits, X);
                uint[] y = Nat.FromBigInteger(bits, Y);
                uint[] r2 = Nat.FromBigInteger(bits, R2);
                uint[] t = new uint[2 * len + 1];
                uint mDash = 0U - Mod.Inverse32(m[0]);

                // the first product leaves X * Y * R^-1, the second multiplies by R^2 * R^-1 to undo it
                MontgomeryMultiply(len, x, y, m, mDash, t, x);
                MontgomeryMultiply(len, x, r2, m, mDash, t, x);
                return Nat.ToBigInteger(len, x);
            }
        }

        /// <summary>
        /// Calculate the modular inverse of a value modulo an odd modulus, in constant time with respect to the value.
        /// </summary>
        /// <param name="M">The odd, positive modulus.</param>
        /// <param name="X">The value to invert.</param>
        /// <returns>The inverse of <paramref name="X"/> modulo <paramref name="M"/>.</returns>
        /// <exception cref="ArgumentException"><paramref name="M"/> is even.</exception>
        /// <exception cref="ArithmeticException">
        /// <paramref name="M"/> is not positive, or <paramref name="X"/> is not invertible.
        /// </exception>
        public static BigInteger ModOddInverse(BigInteger M, BigInteger X) =>
            ImplModOddInverse(M, X) ?? throw new ArithmeticException("BigInteger not invertible");

        // null when X is not invertible
        private static BigInteger ImplModOddInverse(BigInteger M, BigInteger X)
        {
            if (!M.TestBit(0))
                throw new ArgumentException("must be odd", nameof(M));
            if (M.SignValue != 1)
                throw new ArithmeticException("BigInteger: modulus not positive");
            if (X.SignValue < 0 || X.BitLength > M.BitLength)
            {
                X = X.Mod(M);
            }

            int bits = M.BitLength;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (bits <= 2048)
            {
                int len = Nat.GetLengthForBits(bits);
                Span<uint> m = stackalloc uint[len];
                Span<uint> x = stackalloc uint[len];
                Span<uint> z = stackalloc uint[len];
                Nat.FromBigInteger(bits, M, m);
                Nat.FromBigInteger(bits, X, x);
                if (0 == Mod.ModOddInverse(m, x, z))
                    return null;
                return Nat.ToBigInteger(len, z);
            }
            else
#endif
            {
                uint[] m = Nat.FromBigInteger(bits, M);
                uint[] x = Nat.FromBigInteger(bits, X);
                int len = m.Length;
                uint[] z = Nat.Create(len);
                if (0 == Mod.ModOddInverse(m, x, z))
                    return null;
                return Nat.ToBigInteger(len, z);
            }
        }

        /// <summary>Calculate the modular inverse of a value modulo an odd modulus, in variable time.</summary>
        /// <param name="M">The odd, positive modulus.</param>
        /// <param name="X">The value to invert.</param>
        /// <returns>The inverse of <paramref name="X"/> modulo <paramref name="M"/>.</returns>
        /// <exception cref="ArgumentException"><paramref name="M"/> is even.</exception>
        /// <exception cref="ArithmeticException">
        /// <paramref name="M"/> is not positive, or <paramref name="X"/> is not invertible.
        /// </exception>
        public static BigInteger ModOddInverseVar(BigInteger M, BigInteger X)
        {
            if (!M.TestBit(0))
                throw new ArgumentException("must be odd", nameof(M));
            if (M.SignValue != 1)
                throw new ArithmeticException("BigInteger: modulus not positive");
            if (M.Equals(One))
                return Zero;
            if (X.SignValue < 0 || X.BitLength > M.BitLength)
            {
                X = X.Mod(M);
            }
            if (X.Equals(One))
                return One;

            int bits = M.BitLength;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (bits <= 2048)
            {
                int len = Nat.GetLengthForBits(bits);
                Span<uint> m = stackalloc uint[len];
                Span<uint> x = stackalloc uint[len];
                Span<uint> z = stackalloc uint[len];
                Nat.FromBigInteger(bits, M, m);
                Nat.FromBigInteger(bits, X, x);
                if (!Mod.ModOddInverseVar(m, x, z))
                    throw new ArithmeticException("BigInteger not invertible");
                return Nat.ToBigInteger(len, z);
            }
            else
#endif
            {
                uint[] m = Nat.FromBigInteger(bits, M);
                uint[] x = Nat.FromBigInteger(bits, X);
                int len = m.Length;
                uint[] z = Nat.Create(len);
                if (!Mod.ModOddInverseVar(m, x, z))
                    throw new ArithmeticException("BigInteger not invertible");
                return Nat.ToBigInteger(len, z);
            }
        }

        /// <summary>
        /// Determine whether a value is coprime to an odd modulus, in constant time with respect to the value.
        /// </summary>
        /// <param name="M">The odd, positive modulus.</param>
        /// <param name="X">The value to test.</param>
        /// <returns>
        /// true if the greatest common divisor of <paramref name="M"/> and <paramref name="X"/> is 1, false otherwise.
        /// </returns>
        /// <exception cref="ArgumentException"><paramref name="M"/> is even.</exception>
        /// <exception cref="ArithmeticException"><paramref name="M"/> is not positive.</exception>
        public static bool ModOddIsCoprime(BigInteger M, BigInteger X)
        {
            if (!M.TestBit(0))
                throw new ArgumentException("must be odd", nameof(M));
            if (M.SignValue != 1)
                throw new ArithmeticException("BigInteger: modulus not positive");
            if (X.SignValue < 0 || X.BitLength > M.BitLength)
            {
                X = X.Mod(M);
            }

            int bits = M.BitLength;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (bits <= 2048)
            {
                int len = Nat.GetLengthForBits(bits);
                Span<uint> m = stackalloc uint[len];
                Span<uint> x = stackalloc uint[len];
                Nat.FromBigInteger(bits, M, m);
                Nat.FromBigInteger(bits, X, x);
                return 0 != Mod.ModOddIsCoprime(m, x);
            }
            else
#endif
            {
                uint[] m = Nat.FromBigInteger(bits, M);
                uint[] x = Nat.FromBigInteger(bits, X);
                return 0 != Mod.ModOddIsCoprime(m, x);
            }
        }

        /// <summary>Determine whether a value is coprime to an odd modulus, in variable time.</summary>
        /// <param name="M">The odd, positive modulus.</param>
        /// <param name="X">The value to test.</param>
        /// <returns>
        /// true if the greatest common divisor of <paramref name="M"/> and <paramref name="X"/> is 1, false otherwise.
        /// </returns>
        /// <exception cref="ArgumentException"><paramref name="M"/> is even.</exception>
        /// <exception cref="ArithmeticException"><paramref name="M"/> is not positive.</exception>
        public static bool ModOddIsCoprimeVar(BigInteger M, BigInteger X)
        {
            if (!M.TestBit(0))
                throw new ArgumentException("must be odd", nameof(M));
            if (M.SignValue != 1)
                throw new ArithmeticException("BigInteger: modulus not positive");
            if (X.SignValue < 0 || X.BitLength > M.BitLength)
            {
                X = X.Mod(M);
            }
            if (X.Equals(One))
                return true;

            int bits = M.BitLength;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (bits <= 2048)
            {
                int len = Nat.GetLengthForBits(bits);
                Span<uint> m = stackalloc uint[len];
                Span<uint> x = stackalloc uint[len];
                Nat.FromBigInteger(bits, M, m);
                Nat.FromBigInteger(bits, X, x);
                return Mod.ModOddIsCoprimeVar(m, x);
            }
            else
#endif
            {
                uint[] m = Nat.FromBigInteger(bits, M);
                uint[] x = Nat.FromBigInteger(bits, X);
                return Mod.ModOddIsCoprimeVar(m, x);
            }
        }

        /// <summary>
        /// X^E mod M for odd M and X in [1, M), with the base blinded so that a chosen X cannot steer the timing.
        /// </summary>
        /// <remarks>
        /// For a fresh random v this computes (X * v)^E * (v^-1)^E. <see cref="BigInteger.ModPow"/> is not constant
        /// time, and with a fixed secret exponent its timing for chosen bases can be accumulated over many calls
        /// (Kocher 1996, Brumley and Boneh 2003); here neither exponentiation sees a base the caller of the enclosing
        /// operation knows. The exponent itself is not randomized: the operations it causes are the same on every
        /// call, so their count remains visible, but once. Costs two exponentiations and an inversion.
        /// </remarks>
        // TODO Replace by a constant-time exponentiation when one is available
        internal static BigInteger ModPowBaseBlinded(BigInteger M, BigInteger X, BigInteger E, SecureRandom random)
        {
            // zero cannot be blinded (the product with v stays zero), and ModMult below rejects X >= M
            if (X.SignValue <= 0)
                throw new ArgumentException("must be positive", nameof(X));

            // the blinding is only as good as v is secret, so v stays on the fixed-time helpers. For a prime M the
            // first v is always invertible; for a composite M, one sharing a factor with M is redrawn.
            BigInteger v, vInv;
            do
            {
                v = CreateRandomInRange(BigInteger.Two, M.Subtract(BigInteger.Two), random);
                vInv = ImplModOddInverse(M, v);
            }
            while (vInv == null);

            BigInteger blinded = ModMult(M, X, v).ModPow(E, M);
            BigInteger unblind = vInv.ModPow(E, M);

            return ModMult(M, blinded, unblind);
        }

        /// <summary>(X - Y) mod M, for X and Y already in [0, M), in time independent of the values.</summary>
        /// <remarks>
        /// Use this rather than <c>X.Subtract(Y).Mod(M)</c> when either operand is secret: reducing a negative value
        /// costs more than a non-negative one, so whether X &lt; Y would be visible. Operands outside [0, M) are
        /// rejected rather than reduced.
        /// </remarks>
        internal static BigInteger ModSubtract(BigInteger M, BigInteger X, BigInteger Y)
        {
            CheckModOperands(M, X, Y);

            // X - Y lies in (-M, M), so one conditional addition of M reduces it; the width is that of ModAdd
            int bits = M.BitLength + 1;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (bits <= 2049)
            {
                int len = Nat.GetLengthForBits(bits);
                Span<uint> m = stackalloc uint[len];
                Span<uint> x = stackalloc uint[len];
                Span<uint> y = stackalloc uint[len];
                Nat.FromBigInteger(bits, M, m);
                Nat.FromBigInteger(bits, X, x);
                Nat.FromBigInteger(bits, Y, y);

                int borrow = Nat.Sub(len, x, y, x);     // borrow is -1 exactly when X < Y
                Nat.Add(len, x, m, y);                  // y = x + M, discarding the carry off the top
                Nat.CMov(len, borrow, y, x);            // take x + M only where the difference went negative
                return Nat.ToBigInteger(len, x);
            }
            else
#endif
            {
                uint[] m = Nat.FromBigInteger(bits, M);
                uint[] x = Nat.FromBigInteger(bits, X);
                uint[] y = Nat.FromBigInteger(bits, Y);
                int len = m.Length;

                int borrow = Nat.Sub(len, x, y, x);     // borrow is -1 exactly when X < Y
                Nat.Add(len, x, m, y);                  // y = x + M, discarding the carry off the top
                Nat.CMov(len, borrow, y, 0, x, 0);      // take x + M only where the difference went negative
                return Nat.ToBigInteger(len, x);
            }
        }

        /// <summary>
        /// Write the unsigned big-endian encoding of a non-negative BigInteger to a stream, without leading zero bytes.
        /// </summary>
        /// <param name="outStr">The stream to write to.</param>
        /// <param name="n">The value to write.</param>
        public static void WriteUnsignedByteArray(Stream outStr, BigInteger n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int length = n.GetLengthofByteArrayUnsigned();
            if (length <= 512)
            {
                Span<byte> buffer = stackalloc byte[length];
                n.ToByteArrayUnsigned(buffer);

                outStr.Write(buffer);
            }
            else
#endif
            {
                byte[] buffer = n.ToByteArrayUnsigned();

                outStr.Write(buffer, 0, buffer.Length);
            }
        }

        private static void CheckModOperands(BigInteger M, BigInteger X, BigInteger Y)
        {
            if (M.SignValue != 1)
                throw new ArithmeticException("BigInteger: modulus not positive");
            if (X.SignValue < 0 || X.CompareTo(M) >= 0 || Y.SignValue < 0 || Y.CompareTo(M) >= 0)
                throw new ArgumentException("'X' and 'Y' must be in the range [0, M)");
        }

        // z = x * y * R^-1 mod m, for R = 2^(32 * len) and x, y in [0, m); z may alias x or y. Coarsely integrated
        // operand scanning over a window of t (2 * len + 1 words) that moves up a word each step, in place of shifting
        // the accumulator: step i adds x * y[i], then the multiple of m that clears the window's bottom word. Every loop
        // runs a fixed number of times and no index depends on the values.
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static void MontgomeryMultiply(int len, ReadOnlySpan<uint> x, ReadOnlySpan<uint> y,
            ReadOnlySpan<uint> m, uint mDash, Span<uint> t, Span<uint> z)
        {
            t.Clear();

            for (int i = 0; i < len; ++i)
            {
                // the window's top word has not been written yet, so it is zero
                Span<uint> w = t.Slice(i, len + 2);

                ulong c = (ulong)Nat.MulWordAddTo(len, y[i], x, w) + w[len];
                w[len] = (uint)c;
                w[len + 1] = (uint)(c >> 32);

                c = (ulong)Nat.MulWordAddTo(len, w[0] * mDash, m, w) + w[len];
                w[len] = (uint)c;
                w[len + 1] += (uint)(c >> 32);
            }

            // the result, below 2m, is in t[len..2len]: subtract m unless it is already below m, which is when the
            // subtraction goes negative and the top word is clear
            ReadOnlySpan<uint> r = t.Slice(len, len + 1);
            uint top = r[len];
            int borrow = Nat.Sub(len, r, m, z);
            int topSet = (int)((top | (0U - top)) >> 31);
            Nat.CMov(len, borrow & (topSet - 1), r, z);
        }
#endif

        private static void MontgomeryMultiply(int len, uint[] x, uint[] y, uint[] m, uint mDash, uint[] t, uint[] z)
        {
            Array.Clear(t, 0, t.Length);

            for (int i = 0; i < len; ++i)
            {
                // the window t[i..i+len+1]: its top word has not been written yet, so it is zero
                ulong c = (ulong)Nat.MulWordAddTo(len, y[i], x, 0, t, i) + t[i + len];
                t[i + len] = (uint)c;
                t[i + len + 1] = (uint)(c >> 32);

                c = (ulong)Nat.MulWordAddTo(len, t[i] * mDash, m, 0, t, i) + t[i + len];
                t[i + len] = (uint)c;
                t[i + len + 1] += (uint)(c >> 32);
            }

            // the result, below 2m, is in t[len..2len]: subtract m unless it is already below m, which is when the
            // subtraction goes negative and the top word is clear
            uint top = t[2 * len];
            int borrow = Nat.Sub(len, t, len, m, 0, z, 0);
            int topSet = (int)((top | (0U - top)) >> 31);
            Nat.CMov(len, borrow & (topSet - 1), t, len, z, 0);
        }
    }
}
