using System;
using System.IO;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMSSigner
        : IMessageSigner
    {
        private LMSPrivateKeyParameters m_privateKey;
        private LMSPublicKeyParameters m_publicKey;

        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                m_privateKey = (LMSPrivateKeyParameters)param;
            }
            else
            {
                m_publicKey = (LMSPublicKeyParameters)param;
            }
        }

        public byte[] GenerateSignature(byte[] message)
        {
            try
            {
                return LMS.GenerateSign(m_privateKey, message).GetEncoded();
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
                return LMS.VerifySignature(m_publicKey, LMSSignature.GetInstance(signature), message);
            }
            catch (IOException e)
            {
                throw new Exception($"unable to decode signature: {e.Message}");
            }
        }
    }
}
