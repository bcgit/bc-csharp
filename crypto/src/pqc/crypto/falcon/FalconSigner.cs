using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public class FalconSigner
        : IMessageSigner
    {
        private byte[] encodedkey;
        private FalconNist nist;

        public void Init(bool forSigning, ICipherParameters param)
        {
            FalconParameters parameters;
            SecureRandom random;

            if (forSigning)
            {
                FalconPrivateKeyParameters skparam;
                if (param is ParametersWithRandom withRandom)
                {
                    skparam = (FalconPrivateKeyParameters)withRandom.Parameters;
                    random = withRandom.Random;
                }
                else
                {
                    skparam = (FalconPrivateKeyParameters)param;
                    random = CryptoServicesRegistrar.GetSecureRandom();
                }
                encodedkey = skparam.GetEncoded();
                parameters = skparam.Parameters;
            }
            else
            {
                FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)param;
                random = null;
                encodedkey = pkparam.GetEncoded();
                parameters = pkparam.Parameters;
            }

            nist = new FalconNist(random, (uint)parameters.LogN, (uint)parameters.NonceLength);
        }

        public byte[] GenerateSignature(byte[] message)
        {
            byte[] sm = new byte[nist.CryptoBytes];

            return nist.crypto_sign(false, sm, message, 0, (uint)message.Length, encodedkey, 0);
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            if (signature[0] != (byte)(0x30 + nist.LogN))
                return false;

            byte[] nonce = new byte[nist.NonceLength];
            byte[] sig = new byte[signature.Length - nist.NonceLength - 1];
            Array.Copy(signature, 1, nonce, 0, nist.NonceLength);
            Array.Copy(signature, nist.NonceLength + 1, sig, 0, signature.Length - nist.NonceLength - 1);
            return nist.crypto_sign_open(false, sig, nonce, message, encodedkey, 0) == 0;
        }
    }
}
