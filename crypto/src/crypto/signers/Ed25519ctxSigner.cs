using System;
using System.IO;
using System.Runtime.CompilerServices;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class Ed25519ctxSigner
        : ISigner
    {
        private readonly Buffer buffer = new Buffer();
        private readonly byte[] context;

        private bool forSigning;
        private Ed25519PrivateKeyParameters privateKey;
        private Ed25519PublicKeyParameters publicKey;

        public Ed25519ctxSigner(byte[] context)
        {
            this.context = Arrays.Clone(context);
        }

        public virtual string AlgorithmName
        {
            get { return "Ed25519ctx"; }
        }

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            this.forSigning = forSigning;

            if (forSigning)
            {
                // TODO Allow IAsymmetricCipherKeyPair to be an ICipherParameters?

                this.privateKey = (Ed25519PrivateKeyParameters)parameters;
                this.publicKey = privateKey.GeneratePublicKey();
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
            buffer.WriteByte(b);
        }

        public virtual void BlockUpdate(byte[] buf, int off, int len)
        {
            buffer.Write(buf, off, len);
        }

        public virtual byte[] GenerateSignature()
        {
            if (!forSigning || null == privateKey)
                throw new InvalidOperationException("Ed25519ctxSigner not initialised for signature generation.");

            return buffer.GenerateSignature(privateKey, publicKey, context);
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning || null == publicKey)
                throw new InvalidOperationException("Ed25519ctxSigner not initialised for verification");

            return buffer.VerifySignature(publicKey, context, signature);
        }

        public virtual void Reset()
        {
            buffer.Reset();
        }

        private class Buffer : MemoryStream
        {
            private readonly object lockObject = new object();

            // https://stackoverflow.com/questions/2223656/what-does-methodimploptions-synchronized-do
            // Not available in lower .net standard versions
            //[MethodImpl(MethodImplOptions.Synchronized)]
            internal byte[] GenerateSignature(Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey, byte[] ctx)
            {
                lock (lockObject)
                {
#if PORTABLE
                    byte[] buf = ToArray();
                    int count = buf.Length;
#else
                    byte[] buf = GetBuffer();
                    int count = (int)Position;
#endif
                    byte[] signature = new byte[Ed25519PrivateKeyParameters.SignatureSize];
                    privateKey.Sign(Ed25519.Algorithm.Ed25519ctx, publicKey, ctx, buf, 0, count, signature, 0);
                    Reset();
                    return signature;
                }
            }

            //[MethodImpl(MethodImplOptions.Synchronized)]
            internal bool VerifySignature(Ed25519PublicKeyParameters publicKey, byte[] ctx, byte[] signature)
            {
                lock (lockObject)
                {
#if PORTABLE
                    byte[] buf = ToArray();
                    int count = buf.Length;
#else
                    byte[] buf = GetBuffer();
                    int count = (int)Position;
#endif
                    byte[] pk = publicKey.GetEncoded();
                    bool result = Ed25519.Verify(signature, 0, pk, 0, ctx, buf, 0, count);
                    Reset();
                    return result;
                }
            }

            //[MethodImpl(MethodImplOptions.Synchronized)]
            internal void Reset()
            {
                lock (lockObject)
                {
#if PORTABLE
                    this.Position = 0L;
                    Streams.WriteZeroes(this, count);
#else
                    Array.Clear(GetBuffer(), 0, (int)Position);
#endif
                    this.Position = 0L;
                }
            }
        }
    }
}
