using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>The result of decoding a record: a buffer region together with the content type.</summary>
    public sealed class TlsDecodeResult
    {
        /// <summary>The buffer holding the decoded data.</summary>
        public readonly byte[] buf;
        /// <summary>The offset into the buffer at which the data starts, and its length.</summary>
        public readonly int off, len;
        /// <summary>The content type of the decoded record.</summary>
        public readonly short contentType;

        /// <summary>Create a new <see cref="TlsDecodeResult"/>.</summary>
        /// <param name="buf">The buffer.</param>
        /// <param name="off">The offset into the array.</param>
        /// <param name="len">The number of bytes.</param>
        /// <param name="contentType">The content type.</param>
        public TlsDecodeResult(byte[] buf, int off, int len, short contentType)
        {
            this.buf = buf;
            this.off = off;
            this.len = len;
            this.contentType = contentType;
        }
    }
}
