using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Signers
{
    public class Ed25519Signer
        : ISigner
    {
        private readonly Buffer buffer = new Buffer();

        private bool forSigning;
        private Ed25519PrivateKeyParameters privateKey;
        private Ed25519PublicKeyParameters publicKey;

        public Ed25519Signer()
        {
        }

        public virtual string AlgorithmName
        {
            get { return "Ed25519"; }
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
                throw new InvalidOperationException("Ed25519Signer not initialised for signature generation.");

            return buffer.GenerateSignature(privateKey, publicKey);
        }

        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning || null == publicKey)
                throw new InvalidOperationException("Ed25519Signer not initialised for verification");

            return buffer.VerifySignature(publicKey, signature);
        }

        public virtual void Reset()
        {
            buffer.Reset();
        }

        private class Buffer : MemoryStream
        {
            internal byte[] GenerateSignature(Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey)
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
                    byte[] signature = new byte[Ed25519PrivateKeyParameters.SignatureSize];
                    privateKey.Sign(Ed25519.Algorithm.Ed25519, publicKey, null, buf, 0, count, signature, 0);
                    Reset();
                    return signature;
                }
            }

            internal bool VerifySignature(Ed25519PublicKeyParameters publicKey, byte[] signature)
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
                    bool result = Ed25519.Verify(signature, 0, pk, 0, buf, 0, count);
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
