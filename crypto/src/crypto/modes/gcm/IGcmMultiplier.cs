using System;

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    /// <summary>Interface for multiplication by a fixed value in the field used by GCM.</summary>
    [Obsolete("Will be removed")]
    public interface IGcmMultiplier
    {
        /// <summary>Initialise the multiplier.</summary>
        /// <param name="H">The hash subkey to multiply by.</param>
        void Init(byte[] H);
        /// <summary>Multiply a value by the hash subkey.</summary>
        /// <param name="x">The value, which is replaced by the product.</param>
        void MultiplyH(byte[] x);
    }
}
