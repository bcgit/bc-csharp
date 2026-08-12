using System;

using Org.BouncyCastle.Crypto;
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
            param = ParameterUtilities.GetRandom(param, out var providedRandom);

            FalconParameters parameters;
            SecureRandom random;

            if (forSigning)
            {
                FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.GetSecureRandom(providedRandom);
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

            nist = new FalconNist(random, parameters.LogN, parameters.NonceLength);
        }

        public byte[] GenerateSignature(byte[] message)
        {
            byte[] sm = new byte[nist.CryptoBytes];

            return nist.CryptoSign(false, sm, message, 0, message.Length, encodedkey, 0);
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            if (signature[0] != (byte)(0x30 + nist.LogN))
                return false;

            int nonceLength = nist.NonceLength;
            byte[] nonce = new byte[nonceLength];
            byte[] sig = new byte[signature.Length - nonceLength - 1];
            Array.Copy(signature, 1, nonce, 0, nonceLength);
            Array.Copy(signature, nonceLength + 1, sig, 0, signature.Length - nonceLength - 1);
            return nist.CryptoSignOpen(false, sig, nonce, message, encodedkey, 0) == 0;
        }
    }
}
