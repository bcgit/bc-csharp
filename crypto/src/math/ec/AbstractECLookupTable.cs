using System;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>Base class for elliptic curve lookup tables.</summary>
    public abstract class AbstractECLookupTable
        : ECLookupTable
    {
        /// <inheritdoc/>
        public abstract ECPoint Lookup(int index);
        /// <inheritdoc/>
        public abstract int Size { get; }

        /// <inheritdoc/>
        public virtual ECPoint LookupVar(int index)
        {
            return Lookup(index);
        }
    }
}
