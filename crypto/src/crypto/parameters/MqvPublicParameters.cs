using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class MqvPublicParameters
        : ICipherParameters
    {
        private readonly ECPublicKeyParameters m_staticPublicKey;
        private readonly ECPublicKeyParameters m_ephemeralPublicKey;

        public MqvPublicParameters(ECPublicKeyParameters staticPublicKey, ECPublicKeyParameters ephemeralPublicKey)
        {
            m_staticPublicKey = staticPublicKey ?? throw new ArgumentNullException(nameof(staticPublicKey));
            m_ephemeralPublicKey = ephemeralPublicKey ?? throw new ArgumentNullException(nameof(ephemeralPublicKey));

            if (!staticPublicKey.Parameters.Equals(ephemeralPublicKey.Parameters))
                throw new ArgumentException("Static and ephemeral public keys have different domain parameters");
        }

        public virtual ECPublicKeyParameters EphemeralPublicKey => m_ephemeralPublicKey;

        public virtual ECPublicKeyParameters StaticPublicKey => m_staticPublicKey;
    }
}
