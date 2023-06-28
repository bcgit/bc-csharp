using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public sealed class PicnicSigner 
        : IMessageSigner
    {
        private PicnicPrivateKeyParameters privKey;
        private PicnicPublicKeyParameters pubKey;

        public PicnicSigner()
        {
        }

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

        public byte[] GenerateSignature(byte[] message)
        {
            PicnicEngine engine = privKey.Parameters.GetEngine();
            byte[] sig = new byte[engine.GetSignatureSize(message.Length)];
            engine.crypto_sign(sig, message, privKey.GetEncoded());

            byte[] signature = new byte[engine.GetTrueSignatureSize()];
            Array.Copy(sig, message.Length + 4, signature, 0, engine.GetTrueSignatureSize());
            return signature;
        }

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