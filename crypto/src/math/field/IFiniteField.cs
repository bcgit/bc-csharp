using System;

namespace Org.BouncyCastle.Math.Field
{
    /// <summary>Interface for a finite field.</summary>
    public interface IFiniteField
    {
        /// <summary>Gets the characteristic.</summary>
        BigInteger Characteristic { get; }

        /// <summary>Gets the dimension.</summary>
        int Dimension { get; }
    }
}
