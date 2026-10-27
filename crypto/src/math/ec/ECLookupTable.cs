using System;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>Interface for a table of points that can be looked up by index.</summary>
    public interface ECLookupTable
    {
        /// <summary>Gets the size.</summary>
        int Size { get; }
        /// <summary>Look up a point by index, in constant time with respect to the index.</summary>
        /// <param name="index">The index.</param>
        /// <returns>The point.</returns>
        ECPoint Lookup(int index);
        /// <summary>Look up a point by index, in variable time.</summary>
        /// <param name="index">The index.</param>
        /// <returns>The point.</returns>
        ECPoint LookupVar(int index);
    }
}
