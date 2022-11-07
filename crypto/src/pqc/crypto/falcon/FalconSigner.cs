using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public class FalconSigner
        : IMessageSigner
    {
        private byte[] encodedkey;
        private FalconNist nist;

        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                if (param is ParametersWithRandom withRandom)
                {
                    FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)withRandom.Parameters;
                    encodedkey = skparam.GetEncoded();
                    nist = new FalconNist(
                        withRandom.Random,
                        (uint)skparam.Parameters.LogN,
                        (uint)skparam.Parameters.NonceLength);
                }
                else
                {
                    FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)param;
                    encodedkey = ((FalconPrivateKeyParameters)param).GetEncoded();
                    nist = new FalconNist(
                        CryptoServicesRegistrar.GetSecureRandom(),
                        (uint)skparam.Parameters.LogN,
                        (uint)skparam.Parameters.NonceLength);
                }
            }
            else
            {
                FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)param;
                encodedkey = pkparam.GetEncoded();
                nist = new FalconNist(
                    CryptoServicesRegistrar.GetSecureRandom(),
                    (uint)pkparam.Parameters.LogN,
                    (uint)pkparam.Parameters.NonceLength);
            }
        }

        public byte[] GenerateSignature(byte[] message)
        {
            byte[] sm = new byte[nist.GetCryptoBytes()];

            return nist.crypto_sign(sm, message, 0, (uint)message.Length, encodedkey, 0);
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            if (signature[0] != (byte)(0x30 + nist.GetLogn()))
            {
                return false;
            }
            byte[] nonce = new byte[nist.GetNonceLength()];
            byte[] sig = new byte[signature.Length - nist.GetNonceLength() - 1];
            Array.Copy(signature, 1, nonce, 0, nist.GetNonceLength());
            Array.Copy(signature, nist.GetNonceLength() + 1, sig, 0, signature.Length - nist.GetNonceLength() - 1);
            bool res = nist.crypto_sign_open(sig,nonce,message,encodedkey,0) == 0;
            return res;
        }
    }
}
