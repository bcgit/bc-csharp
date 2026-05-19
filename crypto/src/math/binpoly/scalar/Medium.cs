namespace Org.BouncyCastle.Math.BinPoly.Scalar
{
    /// <summary>
    /// Sealed <see cref="IBinPolyMul"/> impl selected on the scalar backend for sizes below
    /// <see cref="Large.KaratsubaCutoff"/>: small enough that the schoolbook leaf beats a
    /// Karatsuba descent. Multiply is a single call to <see cref="Kernels.ImplMul"/>
    /// followed by the reduction. The algorithm inside is the table-based scalar
    /// schoolbook.
    /// </summary>
    internal sealed class Medium
        : BinPolyMulBase
    {
        internal Medium(int n, IReduce reduce)
            : base(n, reduce)
        {
        }

        public override void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
            ulong[] tt = new ulong[m_sizeExt];
            Kernels.ImplMul(m_size, x, xOff, y, yOff, tt, 0);
            m_reduce.Reduce(tt, 0, z, zOff);
            BinPolys.Clear(m_sizeExt, tt, 0);
        }
    }
}
