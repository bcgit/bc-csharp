using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Ed25519 public key (RFC 8032). Wraps a decoded curve point obtained from a 32-byte encoded
    /// representation; the point is validated at construction so that subsequent verifications work
    /// against a known-good key.
    /// </summary>
    public sealed class Ed25519PublicKeyParameters
        : AsymmetricKeyParameter
    {
        /// <summary>Length in bytes of an Ed25519 public key encoding (32).</summary>
        public static readonly int KeySize = Ed25519.PublicKeySize;

        private readonly Ed25519.PublicPoint m_publicPoint;

        /// <summary>
        /// Construct from a 32-byte buffer holding the encoded public point.
        /// </summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>, or the encoding does not decode to a valid curve point.</exception>
        public Ed25519PublicKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        /// <summary>
        /// Construct from <paramref name="buf"/> starting at <paramref name="off"/>; reads
        /// <see cref="KeySize"/> bytes.
        /// </summary>
        /// <exception cref="ArgumentException">If the encoded bytes do not decode to a valid curve
        /// point.</exception>
        public Ed25519PublicKeyParameters(byte[] buf, int off)
            : base(false)
        {
            m_publicPoint = Parse(buf, off);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Construct from a span holding the encoded public point.
        /// </summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>, or the encoding does not decode to a valid curve point.</exception>
        public Ed25519PublicKeyParameters(ReadOnlySpan<byte> buf)
            : base(false)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            m_publicPoint = Parse(buf);
        }
#endif

        /// <summary>
        /// Read <see cref="KeySize"/> encoded bytes from <paramref name="input"/> and decode them.
        /// </summary>
        /// <exception cref="EndOfStreamException">If the stream ends before <see cref="KeySize"/>
        /// bytes have been read.</exception>
        /// <exception cref="ArgumentException">If the encoded bytes do not decode to a valid curve
        /// point.</exception>
        public Ed25519PublicKeyParameters(Stream input)
            : base(false)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> data = stackalloc byte[KeySize];
#else
            byte[] data = new byte[KeySize];
#endif

            if (KeySize != Streams.ReadFully(input, data))
                throw new EndOfStreamException("EOF encountered in middle of Ed25519 public key");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            m_publicPoint = Parse(data);
#else
            m_publicPoint = Parse(data, 0);
#endif
        }

        /// <summary>
        /// Construct from an already-decoded curve point. No further validation is performed.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="publicPoint"/> is <c>null</c>.</exception>
        public Ed25519PublicKeyParameters(Ed25519.PublicPoint publicPoint)
            : base(false)
        {
            m_publicPoint = publicPoint ?? throw new ArgumentNullException(nameof(publicPoint));
        }

        /// <summary>
        /// Write the 32-byte encoded public point into <paramref name="buf"/> at <paramref name="off"/>.
        /// </summary>
        public void Encode(byte[] buf, int off)
        {
            Ed25519.EncodePublicPoint(m_publicPoint, buf, off);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the 32-byte encoded public point into the supplied span.</summary>
        public void Encode(Span<byte> buf)
        {
            Ed25519.EncodePublicPoint(m_publicPoint, buf);
        }
#endif

        /// <summary>Return a fresh copy of the 32-byte encoded public point.</summary>
        public byte[] GetEncoded()
        {
            byte[] data = new byte[KeySize];
            Encode(data, 0);
            return data;
        }

        /// <summary>
        /// Verify an Ed25519 signature. Selects between pure Ed25519, Ed25519ctx and Ed25519ph based on
        /// <paramref name="algorithm"/>. The pure variant rejects a non-<c>null</c> context; the context
        /// and prehash variants require a context up to 255 bytes long, and Ed25519ph additionally
        /// requires <paramref name="msgLen"/> to equal <see cref="Ed25519.PrehashSize"/>.
        /// </summary>
        /// <returns><c>true</c> if the signature is valid for this key; otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="ctx"/> is required but
        /// <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If <paramref name="ctx"/> exceeds 255 bytes,
        /// is supplied for pure Ed25519, <paramref name="msgLen"/> is wrong for Ed25519ph, or
        /// <paramref name="algorithm"/> is unrecognised.</exception>
        public bool Verify(Ed25519.Algorithm algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen,
            byte[] sig, int sigOff)
        {
            switch (algorithm)
            {
            case Ed25519.Algorithm.Ed25519:
            {
                if (null != ctx)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed25519.Verify(sig, sigOff, m_publicPoint, msg, msgOff, msgLen);
            }
            case Ed25519.Algorithm.Ed25519ctx:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed25519.Verify(sig, sigOff, m_publicPoint, ctx, msg, msgOff, msgLen);
            }
            case Ed25519.Algorithm.Ed25519ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));
                if (Ed25519.PrehashSize != msgLen)
                    throw new ArgumentOutOfRangeException(nameof(msgLen));

                return Ed25519.VerifyPrehash(sig, sigOff, m_publicPoint, ctx, msg, msgOff);
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
        /// <see cref="Verify(Ed25519.Algorithm, byte[], byte[], int, int, byte[], int)"/>.
        /// </summary>
        public bool Verify(Ed25519.Algorithm algorithm, byte[] ctx, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> sig)
        {
            switch (algorithm)
            {
            case Ed25519.Algorithm.Ed25519:
            {
                if (null != ctx)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed25519.Verify(sig, m_publicPoint, msg);
            }
            case Ed25519.Algorithm.Ed25519ctx:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed25519.Verify(sig, m_publicPoint, ctx, msg);
            }
            case Ed25519.Algorithm.Ed25519ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed25519.VerifyPrehash(sig, m_publicPoint, ctx, ph: msg);
            }
            default:
            {
                throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
            }
        }
#endif

        private static Ed25519.PublicPoint Parse(byte[] buf, int off)
        {
            return Ed25519.ValidatePublicKeyPartialExport(buf, off)
                ?? throw new ArgumentException("invalid public key");
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static Ed25519.PublicPoint Parse(ReadOnlySpan<byte> buf)
        {
            return Ed25519.ValidatePublicKeyPartialExport(buf)
                ?? throw new ArgumentException("invalid public key");
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
