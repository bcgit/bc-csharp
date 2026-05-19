namespace Org.BouncyCastle.Math.BinPoly
{
    /// <summary>
    /// Multiplicative inversion in the field <c>GF(2^n) = GF(2)[x] / f(x)</c>.
    /// </summary>
    /// <remarks>
    /// <para>Instances are produced by the static factories on <see cref="BinPolys.Inv"/>.
    /// Inversion is only well-defined when the reduction polynomial backing the supplied
    /// <see cref="IBinPolyMul"/> is <b>irreducible</b>, so that the quotient ring is a field. The
    /// binomial reducer (<c>x^n + 1</c>) is always reducible (<c>x = 1</c> is a root over
    /// <c>GF(2)</c>) and must <b>not</b> be used. Irreducibility is the caller's attestation — it is
    /// not checked, and a reducible polynomial yields a meaningless result (or stumbles on a
    /// non-invertible element).</para>
    /// <para>Polynomials are stored bit-packed in <c>ulong[]</c> with little-endian word order, the
    /// same representation as <see cref="IBinPolyMul"/>.</para>
    /// </remarks>
    internal interface IBinPolyInv
    {
        /// <summary>Polynomial bit-length <c>n</c>.</summary>
        int N { get; }

        /// <summary>Number of <c>ulong</c> limbs required to hold a polynomial of length <see cref="N"/>.</summary>
        int Size { get; }

        /// <summary>
        /// Compute <c>z = x^{-1} mod f(x)</c>. By convention <c>0</c> maps to <c>0</c> — there is no
        /// special case for it (nor for <c>1</c>); both fall out of the computation, so the running
        /// cost is independent of the element value. <c>x</c> may alias <c>z</c>.
        /// </summary>
        void Invert(ulong[] x, int xOff, ulong[] z, int zOff);
    }
}
