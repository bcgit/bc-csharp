using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class Ed25519phSigner
        : ISigner
    {
        private readonly IDigest prehash = Ed25519.CreatePrehash();
        private readonly byte[] context;

        private bool forSigning;
        private Ed25519PrivateKeyParameters privateKey;
        private Ed25519PublicKeyParameters publicKey;

        public Ed25519phSigner(byte[] context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            this.context = (byte[])context.Clone();
        }

        public virtual string AlgorithmName
        {
            get { return "Ed25519ph"; }
        }

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            this.forSigning = forSigning;

            if (forSigning)
            {
                this.privateKey = (Ed25519PrivateKeyParameters)parameters;
                this.publicKey = null;
            }
            else
            {
                this.privateKey = null;
                this.publicKey = (Ed25519PublicKeyParameters)parameters;
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

        public virtual int GetMaxSignatureSize() => Ed25519.SignatureSize;

        public virtual byte[] GenerateSignature()
        {
            if (!forSigning || null == privateKey)
                throw new InvalidOperationException("Ed25519phSigner not initialised for signature generation.");

            byte[] msg = new byte[Ed25519.PrehashSize];
            if (Ed25519.PrehashSize != prehash.DoFinal(msg, 0))
                throw new InvalidOperationException("Prehash calculation failed");

            byte[] signature = new byte[Ed25519PrivateKeyParameters.SignatureSize];
            privateKey.Sign(Ed25519.Algorithm.Ed25519ph, context, msg, 0, Ed25519.PrehashSize, signature, 0);
            return signature;
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning || null == publicKey)
                throw new InvalidOperationException("Ed25519phSigner not initialised for verification");
            if (Ed25519.SignatureSize != signature.Length)
            {
                prehash.Reset();
                return false;
            }

            byte[] msg = new byte[Ed25519.PrehashSize];
            if (Ed25519.PrehashSize != prehash.DoFinal(msg, 0))
                throw new InvalidOperationException("Prehash calculation failed");

            return publicKey.Verify(Ed25519.Algorithm.Ed25519ph, context, msg, 0, Ed25519.PrehashSize, signature, 0);
        }

        public void Reset()
        {
            prehash.Reset();
        }
    }
}
