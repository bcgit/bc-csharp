using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <remarks>No longer provides any laziness.</remarks>
    [Obsolete("Will be removed")]
    public class LazyAsn1InputStream
        : Asn1InputStream
    {
        public LazyAsn1InputStream(byte[] input)
            : base(input)
        {
        }

        public LazyAsn1InputStream(Stream inputStream)
            : base(inputStream)
        {
        }

        public LazyAsn1InputStream(Stream input, int limit)
            : base(input, limit)
        {
        }

        public LazyAsn1InputStream(Stream input, int limit, bool leaveOpen)
            : base(input, limit, leaveOpen)
        {
        }
    }
}
