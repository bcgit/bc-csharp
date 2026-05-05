using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Ed25519 private key (RFC 8032). Holds the 32-byte secret seed; the corresponding public key is
    /// derived lazily on first use and cached.
    /// </summary>
    public sealed class Ed25519PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        /// <summary>Length in bytes of an Ed25519 private-key seed (32).</summary>
        public static readonly int KeySize = Ed25519.SecretKeySize;

        /// <summary>Length in bytes of an Ed25519 signature (64).</summary>
        public static readonly int SignatureSize = Ed25519.SignatureSize;

        private readonly byte[] data = new byte[KeySize];

        private Ed25519PublicKeyParameters cachedPublicKey;

        /// <summary>Generate a fresh random Ed25519 private key using <paramref name="random"/>.</summary>
        public Ed25519PrivateKeyParameters(SecureRandom random)
            : base(true)
        {
            Ed25519.GeneratePrivateKey(random, data);
        }

        /// <summary>Construct from a 32-byte seed buffer.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public Ed25519PrivateKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        /// <summary>Construct from <paramref name="buf"/> at <paramref name="off"/>; reads
        /// <see cref="KeySize"/> bytes.</summary>
        public Ed25519PrivateKeyParameters(byte[] buf, int off)
            : base(true)
        {
            Array.Copy(buf, off, data, 0, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Construct from a span carrying the 32-byte seed.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public Ed25519PrivateKeyParameters(ReadOnlySpan<byte> buf)
            : base(true)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            buf.CopyTo(data);
        }
#endif

        /// <summary>Read the 32-byte seed from <paramref name="input"/>.</summary>
        /// <exception cref="EndOfStreamException">If the stream ends before <see cref="KeySize"/>
        /// bytes have been read.</exception>
        public Ed25519PrivateKeyParameters(Stream input)
            : base(true)
        {
            if (KeySize != Streams.ReadFully(input, data))
                throw new EndOfStreamException("EOF encountered in middle of Ed25519 private key");
        }

        /// <summary>Write the 32-byte seed into <paramref name="buf"/> at <paramref name="off"/>.</summary>
        public void Encode(byte[] buf, int off)
        {
            Array.Copy(data, 0, buf, off, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the 32-byte seed into the supplied span.</summary>
        public void Encode(Span<byte> buf)
        {
            data.CopyTo(buf);
        }
#endif

        /// <summary>Return a fresh copy of the 32-byte seed.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(data);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> DataSpan => data;

        internal ReadOnlyMemory<byte> DataMemory => data;
#endif

        /// <summary>
        /// Derive (and cache) the public key corresponding to this private key.
        /// </summary>
        public Ed25519PublicKeyParameters GeneratePublicKey() =>
            Objects.EnsureSingletonInitialized(ref cachedPublicKey, data, CreatePublicKey);

        /// <summary>
        /// Compute an Ed25519 signature. Selects between pure Ed25519, Ed25519ctx and Ed25519ph based on
        /// <paramref name="algorithm"/>. The pure variant rejects a non-<c>null</c> context; the context
        /// and prehash variants require a context up to 255 bytes long, and Ed25519ph additionally
        /// requires <paramref name="msgLen"/> to equal <see cref="Ed25519.PrehashSize"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="ctx"/> is required but
        /// <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If <paramref name="ctx"/> exceeds 255 bytes,
        /// is supplied for pure Ed25519, <paramref name="msgLen"/> is wrong for Ed25519ph, or
        /// <paramref name="algorithm"/> is unrecognised.</exception>
        public void Sign(Ed25519.Algorithm algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen,
            byte[] sig, int sigOff)
        {
            Ed25519PublicKeyParameters publicKey = GeneratePublicKey();

            byte[] pk = new byte[Ed25519.PublicKeySize];
            publicKey.Encode(pk, 0);

            switch (algorithm)
            {
            case Ed25519.Algorithm.Ed25519:
            {
                if (null != ctx)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed25519.Sign(data, 0, pk, 0, msg, msgOff, msgLen, sig, sigOff);
                break;
            }
            case Ed25519.Algorithm.Ed25519ctx:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed25519.Sign(data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
                break;
            }
            case Ed25519.Algorithm.Ed25519ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));
                if (Ed25519.PrehashSize != msgLen)
                    throw new ArgumentOutOfRangeException(nameof(msgLen));

                Ed25519.SignPrehash(data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
                break;
            }
            default:
            {
                throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Span-based overload of
        /// <see cref="Sign(Ed25519.Algorithm, byte[], byte[], int, int, byte[], int)"/>.
        /// </summary>
        public void Sign(Ed25519.Algorithm algorithm, byte[] ctx, ReadOnlySpan<byte> msg, Span<byte> sig)
        {
            Ed25519PublicKeyParameters publicKey = GeneratePublicKey();

            Span<byte> pk = stackalloc byte[Ed25519.PublicKeySize];
            publicKey.Encode(pk);

            switch (algorithm)
            {
            case Ed25519.Algorithm.Ed25519:
            {
                if (null != ctx)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed25519.Sign(data, pk, msg, sig);
                break;
            }
            case Ed25519.Algorithm.Ed25519ctx:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed25519.Sign(data, pk, ctx, msg, sig);
                break;
            }
            case Ed25519.Algorithm.Ed25519ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed25519.SignPrehash(data, pk, ctx, ph: msg, sig);
                break;
            }
            default:
            {
                throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
            }
        }
#endif

        private static Ed25519PublicKeyParameters CreatePublicKey(byte[] data) =>
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            new Ed25519PublicKeyParameters(Ed25519.GeneratePublicKey(data));
#else
            new Ed25519PublicKeyParameters(Ed25519.GeneratePublicKey(data, 0));
#endif

        private static byte[] Validate(byte[] buf)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            return buf;
        }
    }
}
