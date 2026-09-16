using System;

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
            if (m_privateKey == null)
                throw new InvalidOperationException("LmsSigner not initialised for signature generation");

            LmsContext context = m_privateKey.GenerateLmsContext();

            context.BlockUpdate(message, 0, message.Length);

            // Not m_privateKey.GenerateSignature(context): for the single-level HSS key accepted above that
            // yields the HSS encoding, whose only difference is the u32str(Nspk = 0) prefix a caller here does
            // not want. Completing the context as LMS gives the same bytes without the prefix to strip off.
            return LmsEngine.GenerateSign(context).GetEncoded();
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            // Checked before the catch below, so a missing init is reported rather than folded into
            // "signature did not verify"
            if (m_publicKey == null)
                throw new InvalidOperationException("LmsSigner not initialised for verification");

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
