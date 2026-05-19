namespace Org.BouncyCastle.Math.BinPoly
{
    /// <summary>
    /// Binary polynomial arithmetic in <c>GF(2)[x] / r(x)</c>, where <c>r(x)</c> is a binomial,
    /// trinomial, or pentanomial.
    /// </summary>
    /// <remarks>
    /// <para>Instances are produced by the static factories on <see cref="BinPolys"/>. Polynomials
    /// are stored bit-packed in <c>ulong[]</c> with little-endian word order. Each arithmetic
    /// method operates on a <see cref="Size"/>-limb slice of every array argument starting at the
    /// supplied offset; the caller is responsible for ensuring those slices are in-bounds.</para>
    /// <para><b>Aliasing contract.</b> The output buffer (<c>z</c>) may alias <i>at most one</i>
    /// input, and only the first input. Specifically:</para>
    /// <list type="bullet">
    /// <item><description><see cref="Multiply"/>: <c>x</c> may alias <c>z</c> (in-place
    /// <c>z = z * y</c>); <c>y</c> must NOT alias <c>z</c>.</description></item>
    /// <item><description><see cref="Square"/> / <see cref="SquareN"/>: <c>x</c> may alias
    /// <c>z</c> (in-place squaring).</description></item>
    /// </list>
    /// <para>Implementations may rely on the disallowed cases NOT occurring; consumers passing
    /// disallowed aliases may produce arbitrary results.</para>
    /// </remarks>
    internal interface IBinPolyMul
    {
        /// <summary>Polynomial bit-length <c>n</c>.</summary>
        int N { get; }

        /// <summary>Number of <c>ulong</c> limbs required to hold a polynomial of length <see cref="N"/>.</summary>
        int Size { get; }

        /// <summary>
        /// Compute <c>z = x * y mod r(x)</c>. <c>x</c> may alias <c>z</c>; <c>y</c> must not
        /// alias <c>z</c>. See the interface remarks for the full aliasing contract.
        /// </summary>
        void Multiply(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff);

        /// <summary>
        /// Compute <c>z = x^2 mod r(x)</c>. <c>x</c> may alias <c>z</c> (in-place squaring).
        /// </summary>
        void Square(ulong[] x, int xOff, ulong[] z, int zOff);

        /// <summary>
        /// Compute <c>z = x^(2^n) mod r(x)</c>, i.e. <paramref name="n"/> repeated squarings.
        /// <c>x</c> may alias <c>z</c> (in-place repeated squaring).
        /// </summary>
        void SquareN(ulong[] x, int xOff, int n, ulong[] z, int zOff);
    }
}
