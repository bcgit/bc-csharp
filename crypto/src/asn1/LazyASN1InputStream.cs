using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <remarks>No longer provides any laziness.</remarks>
    [Obsolete("Will be removed")]
    public class LazyAsn1InputStream
        : Asn1InputStream
    {
        /// <summary>Create a new <see cref="LazyAsn1InputStream"/>.</summary>
        /// <param name="input">The input data.</param>
        public LazyAsn1InputStream(byte[] input)
            : base(input)
        {
        }

        /// <summary>Create a new <see cref="LazyAsn1InputStream"/>.</summary>
        /// <param name="inputStream">The input stream.</param>
        public LazyAsn1InputStream(Stream inputStream)
            : base(inputStream)
        {
        }

        /// <summary>Create a new <see cref="LazyAsn1InputStream"/>.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="limit">The limit.</param>
        public LazyAsn1InputStream(Stream input, int limit)
            : base(input, limit)
        {
        }

        /// <summary>Create a new <see cref="LazyAsn1InputStream"/>.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="limit">The limit.</param>
        /// <param name="leaveOpen">true if leave open, false otherwise.</param>
        public LazyAsn1InputStream(Stream input, int limit, bool leaveOpen)
            : base(input, limit, leaveOpen)
        {
        }
    }
}
