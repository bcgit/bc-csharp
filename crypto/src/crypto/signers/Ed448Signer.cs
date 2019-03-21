using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class Ed448Signer
        : ISigner
    {
        private readonly Buffer buffer = new Buffer();
        private readonly byte[] context;

        private bool forSigning;
        private Ed448PrivateKeyParameters privateKey;
        private Ed448PublicKeyParameters publicKey;

        public Ed448Signer(byte[] context)
        {
            this.context = Arrays.Clone(context);
        }

        public virtual string AlgorithmName
        {
            get { return "Ed448"; }
        }

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            this.forSigning = forSigning;

            if (forSigning)
            {
                // TODO Allow IAsymmetricCipherKeyPair to be an ICipherParameters?

                this.privateKey = (Ed448PrivateKeyParameters)parameters;
                this.publicKey = privateKey.GeneratePublicKey();
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
            buffer.WriteByte(b);
        }

        public virtual void BlockUpdate(byte[] buf, int off, int len)
        {
            buffer.Write(buf, off, len);
        }

        public virtual byte[] GenerateSignature()
        {
            if (!forSigning || null == privateKey)
                throw new InvalidOperationException("Ed448Signer not initialised for signature generation.");

            return buffer.GenerateSignature(privateKey, publicKey, context);
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning || null == publicKey)
                throw new InvalidOperationException("Ed448Signer not initialised for verification");

            return buffer.VerifySignature(publicKey, context, signature);
        }

        public virtual void Reset()
        {
            buffer.Reset();
        }

        private class Buffer : MemoryStream
        {
            internal byte[] GenerateSignature(Ed448PrivateKeyParameters privateKey, Ed448PublicKeyParameters publicKey, byte[] ctx)
            {
                lock (this)
                {
#if PORTABLE
                byte[] buf = ToArray();
                int count = buf.Length;
#else
                    byte[] buf = GetBuffer();
                    int count = (int)Position;
#endif
                    byte[] signature = new byte[Ed448PrivateKeyParameters.SignatureSize];
                    privateKey.Sign(Ed448.Algorithm.Ed448, publicKey, ctx, buf, 0, count, signature, 0);
                    Reset();
                    return signature;
                }
            }

            internal bool VerifySignature(Ed448PublicKeyParameters publicKey, byte[] ctx, byte[] signature)
            {
                lock (this)
                {
#if PORTABLE
                    byte[] buf = ToArray();
                    int count = buf.Length;
#else
                    byte[] buf = GetBuffer();
                    int count = (int)Position;
#endif
                    byte[] pk = publicKey.GetEncoded();
                    bool result = Ed448.Verify(signature, 0, pk, 0, ctx, buf, 0, count);
                    Reset();
                    return result;
                }
            }

            internal void Reset()
            {
                lock (this)
                {
                    long count = Position;
#if PORTABLE
                    this.Position = 0L;
                    Streams.WriteZeroes(this, count);
#else
                    Array.Clear(GetBuffer(), 0, (int)count);
#endif
                    this.Position = 0L;
                }
            }
        }
    }
}
