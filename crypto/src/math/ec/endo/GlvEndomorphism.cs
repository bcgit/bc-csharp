using System;

namespace Org.BouncyCastle.Math.EC.Endo
{
    /// <summary>Interface for the GLV endomorphism of an elliptic curve.</summary>
    public interface GlvEndomorphism
        :   ECEndomorphism
    {
        /// <summary>Decompose a scalar k into two parts k1 and k2 such that k = k1 + k2 * lambda.</summary>
        /// <param name="k">The scalar.</param>
        /// <returns>The two parts.</returns>
        BigInteger[] DecomposeScalar(BigInteger k);
    }
}
