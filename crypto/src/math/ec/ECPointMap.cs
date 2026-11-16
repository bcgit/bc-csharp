using System;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>Interface for a mapping from points to points of a curve.</summary>
    public interface ECPointMap
    {
        /// <summary>Map a point.</summary>
        /// <param name="p">The point.</param>
        /// <returns>The mapped point.</returns>
        ECPoint Map(ECPoint p);
    }
}
