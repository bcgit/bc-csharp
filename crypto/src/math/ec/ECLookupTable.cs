using System;

namespace Org.BouncyCastle.Math.EC
{
    public interface ECLookupTable
    {
        /// <summary>Gets the size.</summary>
        int Size { get; }
        ECPoint Lookup(int index);
        ECPoint LookupVar(int index);
    }
}
