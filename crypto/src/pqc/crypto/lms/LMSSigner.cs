using System;
using System.IO;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsSigner
        : IMessageSigner
    {
        private LmsPrivateKeyParameters m_privateKey;
        private LmsPublicKeyParameters m_publicKey;

        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                m_privateKey = (LmsPrivateKeyParameters)param;
            }
            else
            {
                m_publicKey = (LmsPublicKeyParameters)param;
            }
        }

        public byte[] GenerateSignature(byte[] message)
        {
            try
            {
                return Lms.GenerateSign(m_privateKey, message).GetEncoded();
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
                return Lms.VerifySignature(m_publicKey, LmsSignature.GetInstance(signature), message);
            }
            catch (InvalidDataException e)
            {
                throw new Exception($"unable to decode signature: {e.Message}");
            }
            catch (IOException e)
            {
                throw new Exception($"unable to decode signature: {e.Message}");
            }
        }
    }
}
