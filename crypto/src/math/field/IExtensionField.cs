using System;

namespace Org.BouncyCastle.Math.Field
{
    /// <summary>Interface for an extension field.</summary>
    public interface IExtensionField
        : IFiniteField
    {
        /// <summary>Gets the subfield.</summary>
        IFiniteField Subfield { get; }

        /// <summary>Gets the degree.</summary>
        int Degree { get; }
    }
}
