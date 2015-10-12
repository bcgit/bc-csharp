using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for operators that serve as stream-based signature verifiers.
    /// </summary>
    public interface ISignatureVerifier
	{
        /// <summary>The algorithm details object for this verifier.</summary>
        Object AlgorithmDetails { get ; }

        /// <summary>Return a "bucket" stream which only exists to update the verifier.</summary>
        /// <returns>A stream to write to in order to update the verifier.</returns>
        Stream GetVerifierUpdater ();

        /// <summary>
        /// Return a stream that wraps the passed in stream, the data written/read to 
        /// the returned stream will update the verifier as well as being passed through.
        /// </summary>
        /// <param name="stream">The stream to be wrapped, must be either readable or writeable, but not both</param>
        /// <returns>A wrapped version of stream which updates the verifier.</returns>
        Stream GetVerifierUpdatingStream (Stream stream);

        /// <summary>
        /// Return true if the passed in signature matches what is expected by the verifier.
        /// </summary>
        /// <param name="signature">The bytes representing the signature.</param>
        /// <returns>true if the signature verifies, false otherwise.</returns>
		bool IsVerified(byte[] signature);

        /// <summary>
        /// Return true if the length bytes from off in the source array match the signature
        /// expected by the verifier.
        /// </summary>
        /// <param name="source">Byte array containing the signature.</param>
        /// <param name="off">The offset into the source array where the signature starts.</param>
        /// <param name="length">The number of bytes in source making up the signature.</param>
        /// <returns>true if the signature verifies, false otherwise.</returns>
		bool IsVerified(byte[] source, int off, int length);
	}
}
