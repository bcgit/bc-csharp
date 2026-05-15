using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// Pure Ed25519 (RFC 8032) signature primitive. Buffers the message via the streaming
    /// <see cref="ISigner"/> surface and dispatches it to the curve routines on finalisation; no
    /// context is permitted.
    /// </summary>
    public class Ed25519Signer
        : ISigner
    {
        private readonly Buffer buffer = new Buffer();

        private bool forSigning;
        private Ed25519PrivateKeyParameters privateKey;
        private Ed25519PublicKeyParameters publicKey;

        /// <summary>Construct an uninitialised pure-Ed25519 signer; call <see cref="Init"/> before use.</summary>
        public Ed25519Signer()
        {
        }

        /// <inheritdoc/>
        public virtual string AlgorithmName
        {
            get { return "Ed25519"; }
        }

        /// <summary>
        /// Initialise for signing (private key) or verification (public key).
        /// </summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="Ed25519PrivateKeyParameters"/> (signing) or
        /// <see cref="Ed25519PublicKeyParameters"/> (verification).</exception>
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

        /// <inheritdoc/>
        public virtual void Update(byte b)
        {
            buffer.WriteByte(b);
        }

        /// <inheritdoc/>
        public virtual void BlockUpdate(byte[] buf, int off, int len)
        {
            buffer.Write(buf, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public virtual void BlockUpdate(ReadOnlySpan<byte> input)
        {
            buffer.Write(input);
        }
#endif

        /// <summary>Length in bytes of an Ed25519 signature (64).</summary>
        public virtual int GetMaxSignatureSize() => Ed25519.SignatureSize;

        /// <summary>Finalise the buffered message and produce the signature. Buffer is reset on return.</summary>
        /// <exception cref="InvalidOperationException">If the signer was initialised for verification,
        /// not signing.</exception>
        public virtual byte[] GenerateSignature()
        {
            if (!forSigning || null == privateKey)
                throw new InvalidOperationException("Ed25519Signer not initialised for signature generation.");

            return buffer.GenerateSignature(privateKey);
        }

        /// <summary>
        /// Finalise the buffered message and verify <paramref name="signature"/>. Buffer is reset on
        /// return.
        /// </summary>
        /// <returns><c>true</c> if the signature is valid for the accumulated message and bound public
        /// key; otherwise <c>false</c>.</returns>
        /// <exception cref="InvalidOperationException">If the signer was initialised for signing, not
        /// verification.</exception>
        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning || null == publicKey)
                throw new InvalidOperationException("Ed25519Signer not initialised for verification");

            return buffer.VerifySignature(publicKey, signature);
        }

        /// <summary>Clear and rewind the buffered message.</summary>
        public virtual void Reset()
        {
            buffer.Reset();
        }

        private sealed class Buffer : MemoryStream
        {
            internal byte[] GenerateSignature(Ed25519PrivateKeyParameters privateKey)
            {
                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    byte[] signature = new byte[Ed25519PrivateKeyParameters.SignatureSize];
                    privateKey.Sign(Ed25519.Algorithm.Ed25519, ctx: null, buf, 0, count, signature, 0);
                    Reset();
                    return signature;
                }
            }

            internal bool VerifySignature(Ed25519PublicKeyParameters publicKey, byte[] signature)
            {
                if (Ed25519.SignatureSize != signature.Length)
                {
                    Reset();
                    return false;
                }

                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    bool result = publicKey.Verify(Ed25519.Algorithm.Ed25519, ctx: null, buf, 0, count, signature, 0);
                    Reset();
                    return result;
                }
            }

            internal void Reset()
            {
                lock (this)
                {
                    int count = Convert.ToInt32(Length);
                    Array.Clear(GetBuffer(), 0, count);
                    SetLength(0);
                }
            }
        }
    }
}
