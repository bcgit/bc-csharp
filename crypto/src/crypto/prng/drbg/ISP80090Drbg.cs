using System;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
    /**
     * Interface to SP800-90A deterministic random bit generators.
     */
    public interface ISP80090Drbg
    {
        /**
         * Return the block size of the DRBG.
         *
         * @return the block size (in bits) produced by each round of the DRBG.
         */
        int BlockSize { get; }

        /**
         * Populate a passed in array with random data.
         *
         * @param output output array for generated bits.
         * @param additionalInput additional input to be added to the DRBG in this step.
         * @param predictionResistant true if a reseed should be forced, false otherwise.
         *
         * @return number of bits generated, -1 if a reseed required.
         */
        int Generate(byte[] output, int outputOff, int outputLen, byte[] additionalInput, bool predictionResistant);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Generate pseudo-random output.</summary>
        /// <param name="output">The span to fill.</param>
        /// <param name="predictionResistant">true if a reseed should be forced, false otherwise.</param>
        /// <returns>The number of bits generated, or -1 if a reseed is required.</returns>
        int Generate(Span<byte> output, bool predictionResistant);

        /// <summary>Generate pseudo-random output with additional input.</summary>
        /// <param name="output">The span to fill.</param>
        /// <param name="additionalInput">The additional input to be added to the DRBG in this step.</param>
        /// <param name="predictionResistant">true if a reseed should be forced, false otherwise.</param>
        /// <returns>The number of bits generated, or -1 if a reseed is required.</returns>
        int GenerateWithInput(Span<byte> output, ReadOnlySpan<byte> additionalInput, bool predictionResistant);
#endif

        /**
         * Reseed the DRBG.
         *
         * @param additionalInput additional input to be added to the DRBG in this step.
         */
        void Reseed(byte[] additionalInput);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Reseed the DRBG.</summary>
        /// <param name="additionalInput">The additional input to be added to the DRBG in this step.</param>
        void Reseed(ReadOnlySpan<byte> additionalInput);
#endif
    }
}
