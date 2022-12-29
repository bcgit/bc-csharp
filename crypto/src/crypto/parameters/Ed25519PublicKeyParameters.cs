using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class Ed25519PublicKeyParameters
        : AsymmetricKeyParameter
    {
        public static readonly int KeySize = Ed25519.PublicKeySize;

        private readonly Ed25519.PublicPoint m_publicPoint;

        public Ed25519PublicKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        public Ed25519PublicKeyParameters(byte[] buf, int off)
            : base(false)
        {
            m_publicPoint = Parse(buf, off);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public Ed25519PublicKeyParameters(ReadOnlySpan<byte> buf)
            : base(false)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            m_publicPoint = Parse(buf);
        }
#endif

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

        public Ed25519PublicKeyParameters(Ed25519.PublicPoint publicPoint)
            : base(false)
        {
            m_publicPoint = publicPoint ?? throw new ArgumentNullException(nameof(publicPoint));
        }

        public void Encode(byte[] buf, int off)
        {
            Ed25519.EncodePublicPoint(m_publicPoint, buf, off);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Encode(Span<byte> buf)
        {
            Ed25519.EncodePublicPoint(m_publicPoint, buf);
        }
#endif

        public byte[] GetEncoded()
        {
            byte[] data = new byte[KeySize];
            Encode(data, 0);
            return data;
        }

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
