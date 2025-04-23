using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    [Obsolete("Use ML-DSA instead")]
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
                if (param is ParametersWithRandom withRandom)
                {
                    privKey = (DilithiumPrivateKeyParameters)withRandom.Parameters;
                    random = withRandom.Random;
                }
                else
                {
                    privKey = (DilithiumPrivateKeyParameters)param;
                    random = null;
                }
            }
            else
            {
                pubKey = (DilithiumPublicKeyParameters)param;
                random = null;
            }
        }

        public byte[] GenerateSignature(byte[] message)
        {
            DilithiumEngine engine = privKey.Parameters.GetEngine(random);
            byte[] sig = new byte[engine.CryptoBytes];
            engine.Sign(sig, sig.Length, message, 0, message.Length, privKey.m_rho, privKey.m_k, privKey.m_tr,
                privKey.m_t0, privKey.m_s1, privKey.m_s2, legacy: true);
            return sig;
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            var engine = pubKey.Parameters.GetEngine(random);
            var tr = DilithiumEngine.CalculatePublicKeyHash(pubKey.m_rho, pubKey.m_t1);
            return engine.VerifyInternal(signature, signature.Length, message, 0, message.Length, pubKey.m_rho,
                pubKey.m_t1, tr);
        }
    }
}
