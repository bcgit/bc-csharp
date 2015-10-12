using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for operators that serve as stream-based signature calculators.
    /// </summary>
    public interface ISignatureCalculator<out A>
	{
        /// <summary>The algorithm details object for this calculator.</summary>
        A AlgorithmDetails { get ; }

        /// <summary>Return a "bucket" stream which only exists to update the calculator.</summary>
        /// <returns>A stream to write to in order to update the calculator.</returns>
        Stream GetSignatureUpdater (); // returns writable stream

        /// <summary>
        /// Return a stream that wraps the passed in stream, the data written/read to 
        /// the returned stream will update the calculator as well as being passed through.
        /// </summary>
        /// <param name="stream">The stream to be wrapped, must be either readable or writeable, but not both</param>
        /// <returns>A wrapped version of stream which updates the calculator.</returns>
        Stream GetSignatureUpdatingStream (Stream stream);

        /// <summary>Calculate the signature and return it as a byte array.</summary>
        /// <returns>The calculated signature.</returns>
        byte[] Signature();

        /// <summary>Calculate the signature and save it in the passed in byte array.</summary>
        /// <param name="destination">The destination array to store the signature in.</param>
        /// <param name="off">The offset into destination to start writing the signature.</param>
        /// <returns>The number of bytes written to destination.</returns>
        int Signature(byte[] destination, int off);
	}
}


