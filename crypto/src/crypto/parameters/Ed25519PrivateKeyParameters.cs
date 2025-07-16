﻿using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class Ed25519PrivateKeyParameters
        : AsymmetricKeyParameter
    {
        public static readonly int KeySize = Ed25519.SecretKeySize;
        public static readonly int SignatureSize = Ed25519.SignatureSize;

        private readonly byte[] data = new byte[KeySize];

        private Ed25519PublicKeyParameters cachedPublicKey;

        public Ed25519PrivateKeyParameters(SecureRandom random)
            : base(true)
        {
            Ed25519.GeneratePrivateKey(random, data);
        }

        public Ed25519PrivateKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        public Ed25519PrivateKeyParameters(byte[] buf, int off)
            : base(true)
        {
            Array.Copy(buf, off, data, 0, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public Ed25519PrivateKeyParameters(ReadOnlySpan<byte> buf)
            : base(true)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            buf.CopyTo(data);
        }
#endif

        public Ed25519PrivateKeyParameters(Stream input)
            : base(true)
        {
            if (KeySize != Streams.ReadFully(input, data))
                throw new EndOfStreamException("EOF encountered in middle of Ed25519 private key");
        }

        public void Encode(byte[] buf, int off)
        {
            Array.Copy(data, 0, buf, off, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Encode(Span<byte> buf)
        {
            data.CopyTo(buf);
        }
#endif

        public byte[] GetEncoded()
        {
            return Arrays.Clone(data);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> DataSpan => data;

        internal ReadOnlyMemory<byte> DataMemory => data;
#endif

        public Ed25519PublicKeyParameters GeneratePublicKey() =>
            Objects.EnsureSingletonInitialized(ref cachedPublicKey, data, CreatePublicKey);

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
