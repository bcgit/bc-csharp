using System;

using System.Linq;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Srp
{
	public class Srp6Utilities
	{
		public static BigInteger CalculateK(IDigest digest, BigInteger N, BigInteger g)
		{
			return HashPaddedPair(digest, N, N, g);
		}

	    public static BigInteger CalculateU(IDigest digest, BigInteger N, BigInteger A, BigInteger B)
	    {
	    	return HashPaddedPair(digest, N, A, B);
	    }

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

        public static byte[] CalculateY(IDigest digest, byte[] salt, byte[] identity)
        {
            byte[] output = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(identity, 0, identity.Length);
            digest.DoFinal(output, 0);
            output = output.Concat(salt).ToArray();
            return output;
        }

        public static BigInteger GeneratePrivateValue(IDigest digest, BigInteger N, BigInteger g, SecureRandom random)
	    {
			int minBits = System.Math.Min(256, N.BitLength / 2);
	        BigInteger min = BigInteger.One.ShiftLeft(minBits - 1);
	        BigInteger max = N.Subtract(BigInteger.One);

	        return BigIntegers.CreateRandomInRange(min, max, random);
	    }

		public static BigInteger ValidatePublicValue(BigInteger N, BigInteger val)
		{
		    val = val.Mod(N);

	        // Check that val % N != 0
	        if (val.Equals(BigInteger.Zero))
	            throw new CryptoException("Invalid public value: 0");

		    return val;
		}

        /** 
         * Computes the client evidence message (M1) according to the standard routine:
         * M1 = H( A | B | S )
         * @param digest The Digest used as the hashing function H
         * @param N Modulus used to get the pad length
         * @param A The public client value
         * @param B The public server value
         * @param S The secret calculated by both sides
         * @return M1 The calculated client evidence message
         */
        public static BigInteger CalculateM1(IDigest digest, BigInteger N, BigInteger A, BigInteger B, BigInteger S)
        {
            BigInteger M1 = HashPaddedTriplet(digest, N, A, B, S);
            return M1;
        }

        /** 
         * Computes the client evidence message (M1) according to the standard routine:
         * M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
         * @param digest The Digest used as the hashing function H
         * @param N Modulus used to get the pad length
         * @param A The public client value
         * @param B The public server value
         * @param K final key
         * @param messageVerifier = H(I) | s
         * @return M1 The calculated client evidence message
         */
        public static BigInteger CalculateM1(IDigest digest, BigInteger N, BigInteger g, BigInteger A, BigInteger B, BigInteger K, byte[] messageVerifier)
        {
            byte[] bA = VALUEOF(A);
            byte[] bB = VALUEOF(B);
            byte[] bK = VALUEOF(K, digest.GetDigestSize());
            byte[] bM1 = SHA(digest, CONCAT(XOR(SHA(digest, N), SHA(digest, g)), CONCAT(messageVerifier, CONCAT(bA, CONCAT(bB, bK)))));
            BigInteger M1 = new BigInteger(1, bM1);
            return M1;
        }

        private static byte[] VALUEOF(BigInteger value, int length = -1)
        {
            int paddedLength = (value.BitLength + 7) / 8;
            if(length > 0)
            {
                paddedLength = length;
            }
            byte[] bytes = new byte[paddedLength];
            BigIntegers.AsUnsignedByteArray(value, bytes, 0, bytes.Length);
            return bytes;
        }

        private static byte[] SHA(IDigest digest, BigInteger value)
        {
            return SHA(digest, value.ToByteArrayUnsigned());
        }

        private static byte[] SHA(IDigest digest, byte[] bytes)
        {
            digest.Reset();
            digest.BlockUpdate(bytes, 0, bytes.Length);
            byte[] rv = new byte[digest.GetDigestSize()];
            digest.DoFinal(rv, 0);
            return rv;
        }

        private static byte[] CONCAT(byte[] a, byte[] b)
        {
            return a.Concat(b).ToArray();
        }

        private static byte[] XOR(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++)
            {
                a[i] ^= b[i];
            }
            return a;
        }

        /** 
         * Computes the server evidence message (M2) according to the standard routine:
         * M2 = H( A | M1 | S )
         * @param digest The Digest used as the hashing function H
         * @param N Modulus used to get the pad length
         * @param A The public client value
         * @param M1 The client evidence message
         * @param S The secret calculated by both sides
         * @return M2 The calculated server evidence message
         */
        public static BigInteger CalculateM2(IDigest digest, BigInteger N, BigInteger A, BigInteger M1, BigInteger S)
        {
            BigInteger M2 = HashPaddedTriplet(digest, N, A, M1, S);
            return M2;
        }

        /**
         * Computes the final Key according to the standard routine: Key = H(S)
         * @param digest The Digest used as the hashing function H
         * @param N Modulus used to get the pad length
         * @param S The secret calculated by both sides
         * @return
         */
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
