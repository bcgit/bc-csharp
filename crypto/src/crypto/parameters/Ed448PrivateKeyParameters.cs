using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Ed448 private key (RFC 8032). Holds the 57-byte secret seed; the corresponding public key is
    /// derived lazily on first use and cached.
    /// </summary>
    public sealed class Ed448PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        /// <summary>Length in bytes of an Ed448 private-key seed (57).</summary>
        public static readonly int KeySize = Ed448.SecretKeySize;

        /// <summary>Length in bytes of an Ed448 signature (114).</summary>
        public static readonly int SignatureSize = Ed448.SignatureSize;

        private readonly byte[] data = new byte[KeySize];

        private Ed448PublicKeyParameters cachedPublicKey;

        /// <summary>Generate a fresh random Ed448 private key using <paramref name="random"/>.</summary>
        public Ed448PrivateKeyParameters(SecureRandom random)
            : base(true)
        {
            Ed448.GeneratePrivateKey(random, data);
        }

        /// <summary>Construct from a 57-byte seed buffer.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public Ed448PrivateKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        /// <summary>Construct from <paramref name="buf"/> at <paramref name="off"/>; reads
        /// <see cref="KeySize"/> bytes.</summary>
        public Ed448PrivateKeyParameters(byte[] buf, int off)
            : base(true)
        {
            Array.Copy(buf, off, data, 0, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Construct from a span carrying the 57-byte seed.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public Ed448PrivateKeyParameters(ReadOnlySpan<byte> buf)
            : base(true)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            buf.CopyTo(data);
        }
#endif

        /// <summary>Read the 57-byte seed from <paramref name="input"/>.</summary>
        /// <exception cref="EndOfStreamException">If the stream ends before <see cref="KeySize"/>
        /// bytes have been read.</exception>
        public Ed448PrivateKeyParameters(Stream input)
            : base(true)
        {
            if (KeySize != Streams.ReadFully(input, data))
                throw new EndOfStreamException("EOF encountered in middle of Ed448 private key");
        }

        /// <summary>Write the 57-byte seed into <paramref name="buf"/> at <paramref name="off"/>.</summary>
        public void Encode(byte[] buf, int off)
        {
            Array.Copy(data, 0, buf, off, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the 57-byte seed into the supplied span.</summary>
        public void Encode(Span<byte> buf)
        {
            data.CopyTo(buf);
        }
#endif

        /// <summary>Return a fresh copy of the 57-byte seed.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(data);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> DataSpan => data;

        internal ReadOnlyMemory<byte> DataMemory => data;
#endif

        /// <summary>Derive (and cache) the public key corresponding to this private key.</summary>
        public Ed448PublicKeyParameters GeneratePublicKey() =>
            Objects.EnsureSingletonInitialized(ref cachedPublicKey, data, CreatePublicKey);

        /// <summary>
        /// Compute an Ed448 signature. Both Ed448 and Ed448ph require a non-<c>null</c> context up to
        /// 255 bytes; Ed448ph additionally requires <paramref name="msgLen"/> to equal
        /// <see cref="Ed448.PrehashSize"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="ctx"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If <paramref name="ctx"/> exceeds 255 bytes,
        /// <paramref name="msgLen"/> is wrong for Ed448ph, or <paramref name="algorithm"/> is
        /// unrecognised.</exception>
        public void Sign(Ed448.Algorithm algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen,
            byte[] sig, int sigOff)
        {
            Ed448PublicKeyParameters publicKey = GeneratePublicKey();

            byte[] pk = new byte[Ed448.PublicKeySize];
            publicKey.Encode(pk, 0);

            switch (algorithm)
            {
            case Ed448.Algorithm.Ed448:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed448.Sign(data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
                break;
            }
            case Ed448.Algorithm.Ed448ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));
                if (Ed448.PrehashSize != msgLen)
                    throw new ArgumentOutOfRangeException(nameof(msgLen));

                Ed448.SignPrehash(data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
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
        /// <see cref="Sign(Ed448.Algorithm, byte[], byte[], int, int, byte[], int)"/>.
        /// </summary>
        public void Sign(Ed448.Algorithm algorithm, byte[] ctx, ReadOnlySpan<byte> msg, Span<byte> sig)
        {
            Ed448PublicKeyParameters publicKey = GeneratePublicKey();

            Span<byte> pk = stackalloc byte[Ed448.PublicKeySize];
            publicKey.Encode(pk);

            switch (algorithm)
            {
            case Ed448.Algorithm.Ed448:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed448.Sign(data, pk, ctx, msg, sig);
                break;
            }
            case Ed448.Algorithm.Ed448ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                Ed448.SignPrehash(data, pk, ctx, ph: msg, sig);
                break;
            }
            default:
            {
                throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
            }
        }
#endif

        private static Ed448PublicKeyParameters CreatePublicKey(byte[] data) =>
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            new Ed448PublicKeyParameters(Ed448.GeneratePublicKey(data));
#else
            new Ed448PublicKeyParameters(Ed448.GeneratePublicKey(data, 0));
#endif

        private static byte[] Validate(byte[] buf)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            return buf;
        }
    }
}
