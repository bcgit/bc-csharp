using System;

namespace Org.BouncyCastle.Math.EC
{
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
