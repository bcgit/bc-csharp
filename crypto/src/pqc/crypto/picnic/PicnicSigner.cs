using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    /// <summary>A Picnic signer.</summary>
    public sealed class PicnicSigner
        : IMessageSigner
    {
        private PicnicPrivateKeyParameters privKey;
        private PicnicPublicKeyParameters pubKey;

        /// <summary>Create a new <see cref="PicnicSigner"/>.</summary>
        public PicnicSigner()
        {
        }

        /// <inheritdoc/>
        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                privKey = (PicnicPrivateKeyParameters) param;
            }
            else
            {
                pubKey = (PicnicPublicKeyParameters) param;
            }

        }

        /// <inheritdoc/>
        public byte[] GenerateSignature(byte[] message)
        {
            PicnicEngine engine = privKey.Parameters.GetEngine();
            byte[] sig = new byte[engine.GetSignatureSize(message.Length)];
            engine.crypto_sign(sig, message, privKey.GetEncoded());

            byte[] signature = new byte[engine.GetTrueSignatureSize()];
            Array.Copy(sig, message.Length + 4, signature, 0, engine.GetTrueSignatureSize());
            return signature;
        }

        /// <inheritdoc/>
        public bool VerifySignature(byte[] message, byte[] signature)
        {
            PicnicEngine engine = pubKey.Parameters.GetEngine();
            byte[] verify_message = new byte[message.Length];
            byte[] attached_signature = Arrays.ConcatenateAll(Pack.UInt32_To_LE((uint)signature.Length), message, signature);

            bool verify = engine.crypto_sign_open(verify_message, attached_signature, pubKey.GetEncoded());
            if (!Arrays.AreEqual(message, verify_message))
                return false;

            return verify;
        }
    }
}
