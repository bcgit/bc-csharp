using System;

namespace Org.BouncyCastle.Math.Field
{
    /// <summary>Interface for an extension field defined by a polynomial.</summary>
    public interface IPolynomialExtensionField
        : IExtensionField
    {
        /// <summary>Gets the minimal polynomial.</summary>
        IPolynomial MinimalPolynomial { get; }
    }
}
