using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    public sealed class TlsDecodeResult
    {
        public readonly byte[] buf;
        public readonly int off, len;
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
