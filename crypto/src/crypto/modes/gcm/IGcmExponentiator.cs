using System;

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    /// <summary>Interface for the exponentiation of x in the field used by GCM.</summary>
    [Obsolete("Will be removed")]
    public interface IGcmExponentiator
    {
        /// <summary>Initialise the exponentiator.</summary>
        /// <param name="x">The value of x.</param>
        void Init(byte[] x);
        /// <summary>Calculate a power of x.</summary>
        /// <param name="pow">The exponent.</param>
        /// <param name="output">The buffer to receive the result.</param>
        void ExponentiateX(long pow, byte[] output);
    }
}
