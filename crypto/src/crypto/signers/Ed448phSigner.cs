﻿using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class Ed448phSigner
        : ISigner
    {
        private readonly IXof prehash = Ed448.CreatePrehash();
        private readonly byte[] context;

        private bool forSigning;
        private Ed448PrivateKeyParameters privateKey;
        private Ed448PublicKeyParameters publicKey;

        public Ed448phSigner(byte[] context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            this.context = (byte[])context.Clone();
        }

        public virtual string AlgorithmName
        {
            get { return "Ed448ph"; }
        }

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            this.forSigning = forSigning;

            if (forSigning)
            {
                this.privateKey = (Ed448PrivateKeyParameters)parameters;
                this.publicKey = null;
            }
            else
            {
                this.privateKey = null;
                this.publicKey = (Ed448PublicKeyParameters)parameters;
            }

            Reset();
        }

        public virtual void Update(byte b)
        {
            prehash.Update(b);
        }

        public virtual void BlockUpdate(byte[] buf, int off, int len)
        {
            prehash.BlockUpdate(buf, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void BlockUpdate(ReadOnlySpan<byte> input)
        {
            prehash.BlockUpdate(input);
        }
#endif

        public virtual int GetMaxSignatureSize() => Ed448.SignatureSize;

        public virtual byte[] GenerateSignature()
        {
            if (!forSigning || null == privateKey)
                throw new InvalidOperationException("Ed448phSigner not initialised for signature generation.");

            byte[] msg = new byte[Ed448.PrehashSize];
            if (Ed448.PrehashSize != prehash.OutputFinal(msg, 0, Ed448.PrehashSize))
                throw new InvalidOperationException("Prehash calculation failed");

            byte[] signature = new byte[Ed448PrivateKeyParameters.SignatureSize];
            privateKey.Sign(Ed448.Algorithm.Ed448ph, context, msg, 0, Ed448.PrehashSize, signature, 0);
            return signature;
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning || null == publicKey)
                throw new InvalidOperationException("Ed448phSigner not initialised for verification");
            if (Ed448.SignatureSize != signature.Length)
            {
                prehash.Reset();
                return false;
            }

            byte[] msg = new byte[Ed448.PrehashSize];
            if (Ed448.PrehashSize != prehash.OutputFinal(msg, 0, Ed448.PrehashSize))
                throw new InvalidOperationException("Prehash calculation failed");

            return publicKey.Verify(Ed448.Algorithm.Ed448ph, context, msg, 0, Ed448.PrehashSize, signature, 0);
        }

        public void Reset()
        {
            prehash.Reset();
        }
    }
}
