using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Srp
{
    /// <summary>Utility methods for the SRP-6 protocol.</summary>
    public class Srp6Utilities
    {
        /// <summary>Calculate the multiplier parameter <c>k = H(N | PAD(g))</c>.</summary>
        /// <param name="digest">The digest to use.</param>
        /// <param name="N">The safe prime modulus.</param>
        /// <param name="g">The generator.</param>
        /// <returns>The value <c>k</c>.</returns>
        public static BigInteger CalculateK(IDigest digest, BigInteger N, BigInteger g)
        {
            return HashPaddedPair(digest, N, N, g);
        }

        /// <summary>Calculate the random scrambling parameter <c>u = H(PAD(A) | PAD(B))</c>.</summary>
        /// <param name="digest">The digest to use.</param>
        /// <param name="N">The safe prime modulus.</param>
        /// <param name="A">The client's public value.</param>
        /// <param name="B">The server's public value.</param>
        /// <returns>The value <c>u</c>.</returns>
        public static BigInteger CalculateU(IDigest digest, BigInteger N, BigInteger A, BigInteger B)
        {
            return HashPaddedPair(digest, N, A, B);
        }

        /// <summary>Calculate the private key <c>x = H(salt | H(identity | ":" | password))</c>.</summary>
        /// <param name="digest">The digest to use.</param>
        /// <param name="N">The safe prime modulus.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="identity">The user identity.</param>
        /// <param name="password">The user password.</param>
        /// <returns>The value <c>x</c>.</returns>
        public static BigInteger CalculateX(IDigest digest, BigInteger N, byte[] salt, byte[] identity, byte[] password)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return CalculateX(digest, N, salt.AsSpan(), identity.AsSpan(), password.AsSpan());
#else
            byte[] output = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(identity, 0, identity.Length);
            digest.Update((byte)':');
            digest.BlockUpdate(password, 0, password.Length);
            digest.DoFinal(output, 0);

            digest.BlockUpdate(salt, 0, salt.Length);
            digest.BlockUpdate(output, 0, output.Length);
            digest.DoFinal(output, 0);

            return new BigInteger(1, output);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Calculate the private key <c>x = H(salt | H(identity | ":" | password))</c>.</summary>
        /// <param name="digest">The digest to use.</param>
        /// <param name="N">The safe prime modulus.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="identity">The user identity.</param>
        /// <param name="password">The user password.</param>
        /// <returns>The value <c>x</c>.</returns>
        public static BigInteger CalculateX(IDigest digest, BigInteger N, ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> identity, ReadOnlySpan<byte> password)
        {
            int digestSize = digest.GetDigestSize();
            Span<byte> output = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];

            digest.BlockUpdate(identity);
            digest.Update((byte)':');
            digest.BlockUpdate(password);
            digest.DoFinal(output);

            digest.BlockUpdate(salt);
            digest.BlockUpdate(output);
            digest.DoFinal(output);

            return new BigInteger(1, output);
        }
#endif

        /// <summary>Generate a random private value in the range allowed for the group.</summary>
        /// <param name="digest">The digest to use.</param>
        /// <param name="N">The safe prime modulus.</param>
        /// <param name="g">The generator.</param>
        /// <param name="random">The source of randomness.</param>
        /// <returns>The private value.</returns>
        public static BigInteger GeneratePrivateValue(IDigest digest, BigInteger N, BigInteger g, SecureRandom random)
        {
            int minBits = System.Math.Min(256, N.BitLength / 2);
            BigInteger min = BigInteger.One.ShiftLeft(minBits - 1);
            BigInteger max = N.Subtract(BigInteger.One);

            return BigIntegers.CreateRandomInRange(min, max, random);
        }

        /// <summary>Validate a public value received from the other party.</summary>
        /// <param name="N">The safe prime modulus.</param>
        /// <param name="val">The public value.</param>
        /// <returns>The public value reduced modulo <paramref name="N"/>.</returns>
        /// <exception cref="CryptoException">The value is zero modulo <paramref name="N"/>.</exception>
        public static BigInteger ValidatePublicValue(BigInteger N, BigInteger val)
        {
            val = val.Mod(N);

            // Check that val % N != 0
            if (val.Equals(BigInteger.Zero))
                throw new CryptoException("Invalid public value: 0");

            return val;
        }

        /// <summary>
        /// Computes the client evidence message (M1) according to the standard routine: M1 = H( A | B | S ).
        /// </summary>
        /// <param name="digest">The Digest used as the hashing function H.</param>
        /// <param name="N">Modulus used to get the pad length.</param>
        /// <param name="A">The public client value.</param>
        /// <param name="B">The public server value.</param>
        /// <param name="S">The secret calculated by both sides.</param>
        /// <returns>M1 The calculated client evidence message.</returns>
        public static BigInteger CalculateM1(IDigest digest, BigInteger N, BigInteger A, BigInteger B, BigInteger S)
        {
            BigInteger M1 = HashPaddedTriplet(digest, N, A, B, S);
            return M1;
        }

        /// <summary>
        /// Computes the server evidence message (M2) according to the standard routine: M2 = H( A | M1 | S ).
        /// </summary>
        /// <param name="digest">The Digest used as the hashing function H.</param>
        /// <param name="N">Modulus used to get the pad length.</param>
        /// <param name="A">The public client value.</param>
        /// <param name="M1">The client evidence message.</param>
        /// <param name="S">The secret calculated by both sides.</param>
        /// <returns>M2 The calculated server evidence message.</returns>
        public static BigInteger CalculateM2(IDigest digest, BigInteger N, BigInteger A, BigInteger M1, BigInteger S)
        {
            BigInteger M2 = HashPaddedTriplet(digest, N, A, M1, S);
            return M2;
        }

        /// <summary>Computes the final Key according to the standard routine: Key = H(S).</summary>
        /// <param name="digest">The Digest used as the hashing function H.</param>
        /// <param name="N">Modulus used to get the pad length.</param>
        /// <param name="S">The secret calculated by both sides.</param>
        /// <returns>The final Key value.</returns>
        public static BigInteger CalculateKey(IDigest digest, BigInteger N, BigInteger S)
        {
            int paddedLength = (N.BitLength + 7) / 8;
            int digestSize = digest.GetDigestSize();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = paddedLength <= 512
                ? stackalloc byte[paddedLength]
                : new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(S, bytes);
            digest.BlockUpdate(bytes);

            Span<byte> output = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            digest.DoFinal(output);
#else
            byte[] bytes = new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(S, bytes, 0, bytes.Length);
            digest.BlockUpdate(bytes, 0, bytes.Length);

            byte[] output = new byte[digestSize];
            digest.DoFinal(output, 0);
#endif

            return new BigInteger(1, output);
        }

        private static BigInteger HashPaddedTriplet(IDigest digest, BigInteger N, BigInteger n1, BigInteger n2, BigInteger n3)
        {
            int paddedLength = (N.BitLength + 7) / 8;
            int digestSize = digest.GetDigestSize();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = paddedLength <= 512
                ? stackalloc byte[paddedLength]
                : new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(n1, bytes);
            digest.BlockUpdate(bytes);
            BigIntegers.AsUnsignedByteArray(n2, bytes);
            digest.BlockUpdate(bytes);
            BigIntegers.AsUnsignedByteArray(n3, bytes);
            digest.BlockUpdate(bytes);

            Span<byte> output = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            digest.DoFinal(output);
#else
            byte[] bytes = new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(n1, bytes, 0, bytes.Length);
            digest.BlockUpdate(bytes, 0, bytes.Length);
            BigIntegers.AsUnsignedByteArray(n2, bytes, 0, bytes.Length);
            digest.BlockUpdate(bytes, 0, bytes.Length);
            BigIntegers.AsUnsignedByteArray(n3, bytes, 0, bytes.Length);
            digest.BlockUpdate(bytes, 0, bytes.Length);

            byte[] output = new byte[digestSize];
            digest.DoFinal(output, 0);
#endif

            return new BigInteger(1, output);
        }

        private static BigInteger HashPaddedPair(IDigest digest, BigInteger N, BigInteger n1, BigInteger n2)
        {
            int paddedLength = (N.BitLength + 7) / 8;
            int digestSize = digest.GetDigestSize();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = paddedLength <= 512
                ? stackalloc byte[paddedLength]
                : new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(n1, bytes);
            digest.BlockUpdate(bytes);
            BigIntegers.AsUnsignedByteArray(n2, bytes);
            digest.BlockUpdate(bytes);

            Span<byte> output = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            digest.DoFinal(output);
#else
            byte[] bytes = new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(n1, bytes, 0, bytes.Length);
            digest.BlockUpdate(bytes, 0, bytes.Length);
            BigIntegers.AsUnsignedByteArray(n2, bytes, 0, bytes.Length);
            digest.BlockUpdate(bytes, 0, bytes.Length);

            byte[] output = new byte[digestSize];
            digest.DoFinal(output, 0);
#endif

            return new BigInteger(1, output);
        }
    }
}
