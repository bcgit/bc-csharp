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
                if (param is HssPrivateKeyParameters hssPriv)
                {
                    if (hssPriv.Level != 1)
                        throw new ArgumentException("only a single level HSS key can be used with LMS");

                    m_privateKey = hssPriv.GetRootKey();
                }
                else
                {
                    m_privateKey = (LmsPrivateKeyParameters)param;
                }

                m_publicKey = null;
            }
            else
            {
                if (param is HssPublicKeyParameters hssPub)
                {
                    if (hssPub.Level != 1)
                        throw new ArgumentException("only a single level HSS key can be used with LMS");

                    m_publicKey = hssPub.LmsPublicKey;
                }
                else
                {
                    m_publicKey = (LmsPublicKeyParameters)param;
                }

                m_privateKey = null;
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
                throw new InvalidOperationException("unable to encode signature", e);
            }
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            try
            {
                return Lms.VerifySignature(m_publicKey, LmsSignature.GetInstance(signature), message);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
