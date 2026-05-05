using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// X25519 private key (RFC 7748). Holds the 32-byte clamped scalar used in Curve25519
    /// Diffie-Hellman.
    /// </summary>
    public sealed class X25519PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        /// <summary>Length in bytes of an X25519 private-key scalar (32).</summary>
        public static readonly int KeySize = X25519.ScalarSize;

        /// <summary>Length in bytes of the shared secret produced by an X25519 agreement (32).</summary>
        public static readonly int SecretSize = X25519.PointSize;

        private readonly byte[] data = new byte[KeySize];

        /// <summary>Generate a fresh random X25519 private key using <paramref name="random"/>.</summary>
        public X25519PrivateKeyParameters(SecureRandom random)
            : base(true)
        {
            X25519.GeneratePrivateKey(random, data);
        }

        /// <summary>Construct from a 32-byte scalar buffer.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public X25519PrivateKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        /// <summary>Construct from <paramref name="buf"/> at <paramref name="off"/>; reads
        /// <see cref="KeySize"/> bytes.</summary>
        public X25519PrivateKeyParameters(byte[] buf, int off)
            : base(true)
        {
            Array.Copy(buf, off, data, 0, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Construct from a span carrying the 32-byte scalar.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public X25519PrivateKeyParameters(ReadOnlySpan<byte> buf)
            : base(true)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            buf.CopyTo(data);
        }
#endif

        /// <summary>Read the 32-byte scalar from <paramref name="input"/>.</summary>
        /// <exception cref="EndOfStreamException">If the stream ends before <see cref="KeySize"/>
        /// bytes have been read.</exception>
        public X25519PrivateKeyParameters(Stream input)
            : base(true)
        {
            if (KeySize != Streams.ReadFully(input, data))
                throw new EndOfStreamException("EOF encountered in middle of X25519 private key");
        }

        /// <summary>Write the 32-byte scalar into <paramref name="buf"/> at <paramref name="off"/>.</summary>
        public void Encode(byte[] buf, int off)
        {
            Array.Copy(data, 0, buf, off, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the 32-byte scalar into the supplied span.</summary>
        public void Encode(Span<byte> buf)
        {
            data.CopyTo(buf);
        }
#endif

        /// <summary>Return a fresh copy of the 32-byte scalar.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(data);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> DataSpan => data;

        internal ReadOnlyMemory<byte> DataMemory => data;
#endif

        /// <summary>Compute the public key (u-coordinate) corresponding to this scalar.</summary>
        public X25519PublicKeyParameters GeneratePublicKey()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> publicKey = stackalloc byte[X25519.PointSize];
            X25519.GeneratePublicKey(data, publicKey);
            return new X25519PublicKeyParameters(publicKey);
#else
            byte[] publicKey = new byte[X25519.PointSize];
            X25519.GeneratePublicKey(data, 0, publicKey, 0);
            return new X25519PublicKeyParameters(publicKey, 0);
#endif
        }

        /// <summary>
        /// Perform an X25519 Diffie-Hellman agreement against <paramref name="publicKey"/> and write the
        /// resulting <see cref="SecretSize"/>-byte shared secret into <paramref name="buf"/> starting at
        /// <paramref name="off"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the agreement produces an all-zero secret
        /// (degenerate peer key).</exception>
        public void GenerateSecret(X25519PublicKeyParameters publicKey, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            GenerateSecret(publicKey, buf.AsSpan(off));
#else
            byte[] encoded = new byte[X25519.PointSize];
            publicKey.Encode(encoded, 0);
            if (!X25519.CalculateAgreement(data, 0, encoded, 0, buf, off))
                throw new InvalidOperationException("X25519 agreement failed");
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Span-based overload of <see cref="GenerateSecret(X25519PublicKeyParameters, byte[], int)"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the agreement produces an all-zero secret.</exception>
        public void GenerateSecret(X25519PublicKeyParameters publicKey, Span<byte> buf)
        {
            Span<byte> encoded = stackalloc byte[X25519.PointSize];
            publicKey.Encode(encoded);
            if (!X25519.CalculateAgreement(data, encoded, buf))
                throw new InvalidOperationException("X25519 agreement failed");
        }
#endif

        private static byte[] Validate(byte[] buf)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            return buf;
        }
    }
}
