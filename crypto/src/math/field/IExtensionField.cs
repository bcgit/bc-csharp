using System;

namespace Org.BouncyCastle.Math.Field
{
    public interface IExtensionField
        : IFiniteField
    {
        /// <summary>Gets the subfield.</summary>
        IFiniteField Subfield { get; }

        /// <summary>Gets the degree.</summary>
        int Degree { get; }
    }
}
