using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Ed448 public key (RFC 8032). Wraps a decoded curve point obtained from a 57-byte encoded
    /// representation; the point is validated at construction.
    /// </summary>
    public sealed class Ed448PublicKeyParameters
        : AsymmetricKeyParameter
    {
        /// <summary>Length in bytes of an Ed448 public key encoding (57).</summary>
        public static readonly int KeySize = Ed448.PublicKeySize;

        private readonly Ed448.PublicPoint m_publicPoint;

        /// <summary>Construct from a 57-byte buffer holding the encoded public point.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>, or the encoding does not decode to a valid curve point.</exception>
        public Ed448PublicKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        /// <summary>Construct from <paramref name="buf"/> at <paramref name="off"/>; reads
        /// <see cref="KeySize"/> bytes.</summary>
        /// <exception cref="ArgumentException">If the encoded bytes do not decode to a valid curve
        /// point.</exception>
        public Ed448PublicKeyParameters(byte[] buf, int off)
            : base(false)
        {
            m_publicPoint = Parse(buf, off);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Construct from a span holding the encoded public point.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>, or the encoding does not decode to a valid curve point.</exception>
        public Ed448PublicKeyParameters(ReadOnlySpan<byte> buf)
            : base(false)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            m_publicPoint = Parse(buf);
        }
#endif

        /// <summary>Read <see cref="KeySize"/> encoded bytes from <paramref name="input"/> and decode them.</summary>
        /// <exception cref="EndOfStreamException">If the stream ends before <see cref="KeySize"/>
        /// bytes have been read.</exception>
        /// <exception cref="ArgumentException">If the encoded bytes do not decode to a valid curve
        /// point.</exception>
        public Ed448PublicKeyParameters(Stream input)
            : base(false)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> data = stackalloc byte[KeySize];
#else
            byte[] data = new byte[KeySize];
#endif

            if (KeySize != Streams.ReadFully(input, data))
                throw new EndOfStreamException("EOF encountered in middle of Ed448 public key");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            m_publicPoint = Parse(data);
#else
            m_publicPoint = Parse(data, 0);
#endif
        }

        /// <summary>Construct from an already-decoded curve point. No further validation is performed.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="publicPoint"/> is <c>null</c>.</exception>
        public Ed448PublicKeyParameters(Ed448.PublicPoint publicPoint)
            : base(false)
        {
            m_publicPoint = publicPoint ?? throw new ArgumentNullException(nameof(publicPoint));
        }

        /// <summary>
        /// Write the 57-byte encoded public point into <paramref name="buf"/> at <paramref name="off"/>.
        /// </summary>
        public void Encode(byte[] buf, int off)
        {
            Ed448.EncodePublicPoint(m_publicPoint, buf, off);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the 57-byte encoded public point into the supplied span.</summary>
        public void Encode(Span<byte> buf)
        {
            Ed448.EncodePublicPoint(m_publicPoint, buf);
        }
#endif

        /// <summary>Return a fresh copy of the 57-byte encoded public point.</summary>
        public byte[] GetEncoded()
        {
            byte[] data = new byte[KeySize];
            Encode(data, 0);
            return data;
        }

        /// <summary>
        /// Verify an Ed448 signature. Both Ed448 and Ed448ph require a non-<c>null</c> context up to
        /// 255 bytes; Ed448ph additionally requires <paramref name="msgLen"/> to equal
        /// <see cref="Ed448.PrehashSize"/>.
        /// </summary>
        /// <returns><c>true</c> if the signature is valid for this key; otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="ctx"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If <paramref name="ctx"/> exceeds 255 bytes,
        /// <paramref name="msgLen"/> is wrong for Ed448ph, or <paramref name="algorithm"/> is
        /// unrecognised.</exception>
        public bool Verify(Ed448.Algorithm algorithm, byte[] ctx, byte[] msg, int msgOff, int msgLen,
            byte[] sig, int sigOff)
        {
            switch (algorithm)
            {
            case Ed448.Algorithm.Ed448:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed448.Verify(sig, sigOff, m_publicPoint, ctx, msg, msgOff, msgLen);
            }
            case Ed448.Algorithm.Ed448ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));
                if (Ed448.PrehashSize != msgLen)
                    throw new ArgumentOutOfRangeException(nameof(msgLen));

                return Ed448.VerifyPrehash(sig, sigOff, m_publicPoint, ctx, msg, msgOff);
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
        /// <see cref="Verify(Ed448.Algorithm, byte[], byte[], int, int, byte[], int)"/>.
        /// </summary>
        public bool Verify(Ed448.Algorithm algorithm, byte[] ctx, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> sig)
        {
            switch (algorithm)
            {
            case Ed448.Algorithm.Ed448:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed448.Verify(sig, m_publicPoint, ctx, msg);
            }
            case Ed448.Algorithm.Ed448ph:
            {
                if (null == ctx)
                    throw new ArgumentNullException(nameof(ctx));
                if (ctx.Length > 255)
                    throw new ArgumentOutOfRangeException(nameof(ctx));

                return Ed448.VerifyPrehash(sig, m_publicPoint, ctx, ph: msg);
            }
            default:
            {
                throw new ArgumentOutOfRangeException(nameof(algorithm));
            }
            }
        }
#endif

        private static Ed448.PublicPoint Parse(byte[] buf, int off)
        {
            return Ed448.ValidatePublicKeyPartialExport(buf, off)
                ?? throw new ArgumentException("invalid public key");
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static Ed448.PublicPoint Parse(ReadOnlySpan<byte> buf)
        {
            return Ed448.ValidatePublicKeyPartialExport(buf)
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
