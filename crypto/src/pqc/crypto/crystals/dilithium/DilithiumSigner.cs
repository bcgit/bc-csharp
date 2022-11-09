using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    public class DilithiumSigner 
        : IMessageSigner
    {
        private DilithiumPrivateKeyParameters privKey;
        private DilithiumPublicKeyParameters pubKey;

        private SecureRandom random;

        public DilithiumSigner()
        {
        }

        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                if (param is ParametersWithRandom)
                {
                    privKey = (DilithiumPrivateKeyParameters)((ParametersWithRandom)param).Parameters;
                    random = ((ParametersWithRandom)param).Random;
                }
                else
                {
                    privKey = (DilithiumPrivateKeyParameters)param;
                    random = null;
                }
            }
            else
            {
                pubKey = (DilithiumPublicKeyParameters) param;
            }

        }

        public byte[] GenerateSignature(byte[] message)
        {
            DilithiumEngine engine = privKey.Parameters.GetEngine(random);
            byte[] sig = new byte[engine.CryptoBytes];
            engine.Sign(sig, sig.Length, message, message.Length, privKey.rho, privKey.k, privKey.tr, privKey.t0, privKey.s1, privKey.s2);
            return sig;
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            DilithiumEngine engine = pubKey.Parameters.GetEngine(random);
            return engine.SignOpen(message,signature, signature.Length, pubKey.rho, pubKey.t1 );
        }
    }
}