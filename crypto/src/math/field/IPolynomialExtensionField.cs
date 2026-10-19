using System;

namespace Org.BouncyCastle.Math.Field
{
    public interface IPolynomialExtensionField
        : IExtensionField
    {
        /// <summary>Gets the minimal polynomial.</summary>
        IPolynomial MinimalPolynomial { get; }
    }
}
