using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.pqc.crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public class PicnicSigner 
        : IMessageSigner
    {
        private PicnicPrivateKeyParameters privKey;
        private PicnicPublicKeyParameters pubKey;

        private SecureRandom random;

        public PicnicSigner(SecureRandom random)
        {
            this.random = random;
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
            PicnicEngine engine = privKey.GetParameters().GetEngine();
            byte[] sig = new byte[engine.GetSignatureSize(message.Length)];
            engine.crypto_sign(sig, message, privKey.GetEncoded());

            return Arrays.CopyOfRange(sig, 0, message.Length + engine.GetTrueSignatureSize());
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            PicnicEngine engine = pubKey.GetParameters().GetEngine();
            byte[] verify_message = new byte[message.Length];
            bool verify = engine.crypto_sign_open(verify_message, signature, pubKey.GetEncoded());
            if (!Arrays.AreEqual(message, verify_message))
            {
                return false;
            }

            return verify;
        }
    }
}