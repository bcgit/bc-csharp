using System;

using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// The private parameters for an MQV key agreement: the static and ephemeral private keys, and optionally the
    /// ephemeral public key.
    /// </summary>
    public class MqvPrivateParameters
        : ICipherParameters
    {
        private readonly ECPrivateKeyParameters staticPrivateKey;
        private readonly ECPrivateKeyParameters ephemeralPrivateKey;
        private readonly ECPublicKeyParameters ephemeralPublicKey;

        /// <summary>Create a new <see cref="MqvPrivateParameters"/>.</summary>
        /// <param name="staticPrivateKey">The static private key.</param>
        /// <param name="ephemeralPrivateKey">The ephemeral private key.</param>
        public MqvPrivateParameters(
            ECPrivateKeyParameters staticPrivateKey,
            ECPrivateKeyParameters ephemeralPrivateKey)
            : this(staticPrivateKey, ephemeralPrivateKey, null)
        {
        }

        /// <summary>Create a new <see cref="MqvPrivateParameters"/>.</summary>
        /// <param name="staticPrivateKey">The static private key.</param>
        /// <param name="ephemeralPrivateKey">The ephemeral private key.</param>
        /// <param name="ephemeralPublicKey">The ephemeral public key.</param>
        public MqvPrivateParameters(
            ECPrivateKeyParameters staticPrivateKey,
            ECPrivateKeyParameters ephemeralPrivateKey,
            ECPublicKeyParameters ephemeralPublicKey)
        {
            if (staticPrivateKey == null)
                throw new ArgumentNullException("staticPrivateKey");
            if (ephemeralPrivateKey == null)
                throw new ArgumentNullException("ephemeralPrivateKey");

            ECDomainParameters parameters = staticPrivateKey.Parameters;
            if (!parameters.Equals(ephemeralPrivateKey.Parameters))
                throw new ArgumentException("Static and ephemeral private keys have different domain parameters");

            if (ephemeralPublicKey == null)
            {
                ECPoint q = new FixedPointCombMultiplier().Multiply(parameters.G, ephemeralPrivateKey.D);

                ephemeralPublicKey = new ECPublicKeyParameters(q, parameters);
            }
            else if (!parameters.Equals(ephemeralPublicKey.Parameters))
            {
                throw new ArgumentException("Ephemeral public key has different domain parameters");
            }

            this.staticPrivateKey = staticPrivateKey;
            this.ephemeralPrivateKey = ephemeralPrivateKey;
            this.ephemeralPublicKey = ephemeralPublicKey;
        }

        /// <summary>Gets the static private key.</summary>
        public virtual ECPrivateKeyParameters StaticPrivateKey
        {
            get { return staticPrivateKey; }
        }

        /// <summary>Gets the ephemeral private key.</summary>
        public virtual ECPrivateKeyParameters EphemeralPrivateKey
        {
            get { return ephemeralPrivateKey; }
        }

        /// <summary>Gets the ephemeral public key.</summary>
        public virtual ECPublicKeyParameters EphemeralPublicKey
        {
            get { return ephemeralPublicKey; }
        }
    }
}
