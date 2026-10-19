using System;

namespace Org.BouncyCastle.Math.Field
{
    public interface IPolynomial
    {
        /// <summary>Gets the degree.</summary>
        int Degree { get; }

        //BigInteger[] GetCoefficients();

        /// <summary>Return the exponents present.</summary>
        int[] GetExponentsPresent();

        //Term[] GetNonZeroTerms();
    }
}
