using System;

namespace Org.BouncyCastle.Math.Field
{
    /// <summary>Interface for a polynomial over a finite field.</summary>
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
