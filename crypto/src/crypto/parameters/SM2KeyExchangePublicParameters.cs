using System;

using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Public parameters for an SM2 key exchange.</summary>
    /// <remarks>In this case the ephemeralPublicKey provides the random point used in the algorithm.</remarks>
    public class SM2KeyExchangePublicParameters
        : ICipherParameters
    {
        private readonly ECPublicKeyParameters mStaticPublicKey;
        private readonly ECPublicKeyParameters mEphemeralPublicKey;

        /// <summary>Create a new <see cref="SM2KeyExchangePublicParameters"/>.</summary>
        /// <param name="staticPublicKey">The static public key.</param>
        /// <param name="ephemeralPublicKey">The ephemeral public key.</param>
        public SM2KeyExchangePublicParameters(
            ECPublicKeyParameters staticPublicKey,
            ECPublicKeyParameters ephemeralPublicKey)
        {
            if (staticPublicKey == null)
                throw new ArgumentNullException("staticPublicKey");
            if (ephemeralPublicKey == null)
                throw new ArgumentNullException("ephemeralPublicKey");
            if (!staticPublicKey.Parameters.Equals(ephemeralPublicKey.Parameters))
                throw new ArgumentException("Static and ephemeral public keys have different domain parameters");

            this.mStaticPublicKey = staticPublicKey;
            this.mEphemeralPublicKey = ephemeralPublicKey;
        }

        /// <summary>Gets the static public key.</summary>
        public virtual ECPublicKeyParameters StaticPublicKey
        {
            get { return mStaticPublicKey; }
        }

        /// <summary>Gets the ephemeral public key.</summary>
        public virtual ECPublicKeyParameters EphemeralPublicKey
        {
            get { return mEphemeralPublicKey; }
        }
    }
}
