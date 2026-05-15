using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary>
    /// Ed448ph (RFC 8032) signature primitive: pre-hashes the message with SHAKE256 before running
    /// pure Ed448, parameterised by a fixed context captured at construction.
    /// </summary>
    public class Ed448phSigner
        : ISigner
    {
        private readonly IXof prehash = Ed448.CreatePrehash();
        private readonly byte[] context;

        private bool forSigning;
        private Ed448PrivateKeyParameters privateKey;
        private Ed448PublicKeyParameters publicKey;

        /// <summary>
        /// Construct an Ed448ph signer bound to the supplied <paramref name="context"/>. The context
        /// bytes are cloned so the caller may mutate the array afterwards.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="context"/> is <c>null</c>.</exception>
        public Ed448phSigner(byte[] context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            this.context = (byte[])context.Clone();
        }

        /// <inheritdoc/>
        public virtual string AlgorithmName
        {
            get { return "Ed448ph"; }
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
            prehash.Update(b);
        }

        /// <inheritdoc/>
        public virtual void BlockUpdate(byte[] buf, int off, int len)
        {
            prehash.BlockUpdate(buf, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public virtual void BlockUpdate(ReadOnlySpan<byte> input)
        {
            prehash.BlockUpdate(input);
        }
#endif

        /// <summary>Length in bytes of an Ed448ph signature (114).</summary>
        public virtual int GetMaxSignatureSize() => Ed448.SignatureSize;

        /// <summary>Finalise the pre-hash and produce the signature.</summary>
        /// <exception cref="InvalidOperationException">If the signer was initialised for verification,
        /// not signing, or the pre-hash finalisation produces an unexpected length.</exception>
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

        /// <summary>Finalise the pre-hash and verify <paramref name="signature"/>.</summary>
        /// <returns><c>true</c> if the signature is valid for the accumulated message, bound public
        /// key and captured context; otherwise <c>false</c>.</returns>
        /// <exception cref="InvalidOperationException">If the signer was initialised for signing, not
        /// verification, or the pre-hash finalisation produces an unexpected length.</exception>
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

        /// <summary>Reset the pre-hash digest; the captured context survives.</summary>
        public void Reset()
        {
            prehash.Reset();
        }
    }
}
