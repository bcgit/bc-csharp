using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>The public parameters for an MQV key agreement: the static and ephemeral public keys.</summary>
    public class MqvPublicParameters
        : ICipherParameters
    {
        private readonly ECPublicKeyParameters m_staticPublicKey;
        private readonly ECPublicKeyParameters m_ephemeralPublicKey;

        /// <summary>Create a new <see cref="MqvPublicParameters"/>.</summary>
        /// <param name="staticPublicKey">The static public key.</param>
        /// <param name="ephemeralPublicKey">The ephemeral public key.</param>
        public MqvPublicParameters(ECPublicKeyParameters staticPublicKey, ECPublicKeyParameters ephemeralPublicKey)
        {
            m_staticPublicKey = staticPublicKey ?? throw new ArgumentNullException(nameof(staticPublicKey));
            m_ephemeralPublicKey = ephemeralPublicKey ?? throw new ArgumentNullException(nameof(ephemeralPublicKey));

            if (!staticPublicKey.Parameters.Equals(ephemeralPublicKey.Parameters))
                throw new ArgumentException("Static and ephemeral public keys have different domain parameters");
        }

        /// <summary>Gets the ephemeral public key.</summary>
        public virtual ECPublicKeyParameters EphemeralPublicKey => m_ephemeralPublicKey;

        /// <summary>Gets the static public key.</summary>
        public virtual ECPublicKeyParameters StaticPublicKey => m_staticPublicKey;
    }
}
