using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class HssSigner
        : IMessageSigner
    {
        private HssPrivateKeyParameters m_privateKey;
        private HssPublicKeyParameters m_publicKey;

        public void Init(bool forSigning, ICipherParameters param)
        {
            param = ParameterUtilities.IgnoreRandom(param);

            if (forSigning)
            {
                m_privateKey = (HssPrivateKeyParameters)param;
                m_publicKey = null;
            }
            else
            {
                m_publicKey = (HssPublicKeyParameters)param;
                m_privateKey = null;
            }
        }

        public byte[] GenerateSignature(byte[] message)
        {
            if (m_privateKey == null)
                throw new InvalidOperationException("HssSigner not initialised for signature generation");

            LmsContext context = m_privateKey.GenerateLmsContext();

            context.BlockUpdate(message, 0, message.Length);

            return m_privateKey.GenerateSignature(context);
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            // Checked before the catch below, so a missing init is reported rather than folded into
            // "signature did not verify"
            if (m_publicKey == null)
                throw new InvalidOperationException("HssSigner not initialised for verification");

            LmsContext context;
            try
            {
                context = m_publicKey.GenerateLmsContext(signature);
            }
            catch (Exception)
            {
                // A malformed signature is a failed verification, not an exception out of Verify. Scoped to the
                // decode alone: past it an inconsistent signature is reported by returning false.
                return false;
            }

            context.BlockUpdate(message, 0, message.Length);

            return m_publicKey.Verify(context);
        }
    }
}
