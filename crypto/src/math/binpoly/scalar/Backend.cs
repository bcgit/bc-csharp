namespace Org.BouncyCastle.Math.BinPoly.Scalar
{
    /// <summary>
    /// Entry point for the Scalar fallback backend. No <c>IsEnabled</c> gate — this
    /// backend is the unconditional last-resort dispatch when no ISA-specific backend
    /// applies. <see cref="CreateBinPolyMul"/> picks <see cref="Medium"/> for sub-cutoff
    /// sizes (direct schoolbook leaf) and <see cref="Large"/> for sizes at or above
    /// the cutoff (Karatsuba recursion).
    /// </summary>
    internal static class Backend
    {
        internal static IBinPolyMul CreateBinPolyMul(int n, BinPolyMulBase.IReduce reduce)
        {
            int size = BinPolys.Size(n);
            if (size < Large.KaratsubaCutoff)
                return new Medium(n, reduce);
            return new Large(n, reduce);
        }
    }
}
