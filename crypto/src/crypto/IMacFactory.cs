using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>Interface for a factory that creates calculators for a message authentication code.</summary>
    // TODO[api] Add 'out A' type parameter for AlgorithmDetails return type
    public interface IMacFactory
    {
        /// <summary>The algorithm details object for this calculator.</summary>
        object AlgorithmDetails { get; }

        /// <summary>
        /// Create a stream calculator for this signature calculator. The stream
        /// calculator is used for the actual operation of entering the data to be signed
        /// and producing the signature block.
        /// </summary>
        /// <returns>A calculator producing an IBlockResult with a signature in it.</returns>
        IStreamCalculator<IBlockResult> CreateCalculator();
    }
}
