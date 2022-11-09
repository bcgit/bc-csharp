using System;
using System.IO;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssSigner 
        : IMessageSigner
    {
        private HssPrivateKeyParameters privKey;
        private HssPublicKeyParameters pubKey;

        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                this.privKey = (HssPrivateKeyParameters) param;
            }
            else
            {
                this.pubKey = (HssPublicKeyParameters) param;
            }
        }

        public byte[] GenerateSignature(byte[] message)
        {
            try
            {
                return Hss.GenerateSignature(privKey, message).GetEncoded();
            }
            catch (IOException e)
            {
                throw new Exception($"unable to encode signature: {e.Message}");
            }
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            try
            {
                return Hss.VerifySignature(pubKey, HssSignature.GetInstance(signature, pubKey.L), message);
            }
            catch (IOException e)
            {
                throw new Exception($"unable to decode signature: {e.Message}");
            }
        }
    }
}
