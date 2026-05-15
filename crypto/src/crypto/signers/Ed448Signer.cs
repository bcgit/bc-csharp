using System;
using System.IO;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// Ed448 (RFC 8032) signature primitive: pure Ed448 with a mandatory domain-separation context of
    /// up to 255 bytes captured at construction.
    /// </summary>
    public class Ed448Signer
        : ISigner
    {
        private readonly Buffer buffer = new Buffer();
        private readonly byte[] context;

        private bool forSigning;
        private Ed448PrivateKeyParameters privateKey;
        private Ed448PublicKeyParameters publicKey;

        /// <summary>
        /// Construct an Ed448 signer bound to the supplied <paramref name="context"/>. The context bytes
        /// are cloned so the caller may mutate the array afterwards.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="context"/> is <c>null</c>.</exception>
        public Ed448Signer(byte[] context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            this.context = (byte[])context.Clone();
        }

        /// <inheritdoc/>
        public virtual string AlgorithmName
        {
            get { return "Ed448"; }
        }

        /// <summary>Initialise for signing (private key) or verification (public key).</summary>
        /// <exception cref="InvalidCastException">If <paramref name="parameters"/> is not an
        /// <see cref="Ed448PrivateKeyParameters"/> (signing) or
        /// <see cref="Ed448PublicKeyParameters"/> (verification).</exception>
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

        /// <summary>Length in bytes of an Ed448 signature (114).</summary>
        public virtual int GetMaxSignatureSize() => Ed448.SignatureSize;

        /// <summary>Finalise the buffered message and produce the signature. Buffer is reset on return.</summary>
        /// <exception cref="InvalidOperationException">If the signer was initialised for verification,
        /// not signing.</exception>
        public virtual byte[] GenerateSignature()
        {
            if (!forSigning || null == privateKey)
                throw new InvalidOperationException("Ed448Signer not initialised for signature generation.");

            return buffer.GenerateSignature(privateKey, context);
        }

        /// <summary>
        /// Finalise the buffered message and verify <paramref name="signature"/>. Buffer is reset on
        /// return.
        /// </summary>
        /// <returns><c>true</c> if the signature is valid for the accumulated message, bound public
        /// key and captured context; otherwise <c>false</c>.</returns>
        /// <exception cref="InvalidOperationException">If the signer was initialised for signing, not
        /// verification.</exception>
        public virtual bool VerifySignature(byte[] signature)
        {
            if (forSigning || null == publicKey)
                throw new InvalidOperationException("Ed448Signer not initialised for verification");

            return buffer.VerifySignature(publicKey, context, signature);
        }

        /// <summary>Clear and rewind the buffered message; the captured context survives.</summary>
        public virtual void Reset()
        {
            buffer.Reset();
        }

        private sealed class Buffer : MemoryStream
        {
            internal byte[] GenerateSignature(Ed448PrivateKeyParameters privateKey, byte[] ctx)
            {
                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    byte[] signature = new byte[Ed448PrivateKeyParameters.SignatureSize];
                    privateKey.Sign(Ed448.Algorithm.Ed448, ctx, buf, 0, count, signature, 0);
                    Reset();
                    return signature;
                }
            }

            internal bool VerifySignature(Ed448PublicKeyParameters publicKey, byte[] ctx, byte[] signature)
            {
                if (Ed448.SignatureSize != signature.Length)
                {
                    Reset();
                    return false;
                }

                lock (this)
                {
                    byte[] buf = GetBuffer();
                    int count = Convert.ToInt32(Length);

                    bool result = publicKey.Verify(Ed448.Algorithm.Ed448, ctx, buf, 0, count, signature, 0);
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
