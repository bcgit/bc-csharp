using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsSigner
        : IMessageSigner
    {
        private ILmsContextBasedSigner m_privateKey;
        private LmsPublicKeyParameters m_publicKey;

        public void Init(bool forSigning, ICipherParameters param)
        {
            param = ParameterUtilities.IgnoreRandom(param);

            if (forSigning)
            {
                if (param is HssPrivateKeyParameters hssPriv)
                {
                    if (hssPriv.Level != 1)
                        throw new ArgumentException("only a single level HSS key can be used with LMS");

                    // Sign through the HSS key so that its index advances with the root tree's q. Signing
                    // the root key directly leaves the index behind, and ResetKeyToIndex (reached from
                    // ExtractKeyShard and the public constructor) would then move the root back to one-time
                    // keys already used. A single-level context carries no signed public keys, so the LMS
                    // signature it yields is the HSS signature without its u32str(Nspk = 0) prefix (RFC 8554
                    // section 6.1).
                    m_privateKey = hssPriv;
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
            LmsContext context = m_privateKey.GenerateLmsContext();

            context.BlockUpdate(message, 0, message.Length);

            try
            {
                return Lms.GenerateSign(context).GetEncoded();
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
