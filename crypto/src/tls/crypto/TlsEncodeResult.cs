using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    public sealed class TlsEncodeResult
    {
        public readonly byte[] buf;
        public readonly int off, len;
        public readonly short recordType;

        /// <summary>Create a new <see cref="TlsEncodeResult"/>.</summary>
        /// <param name="buf">The buffer.</param>
        /// <param name="off">The offset into the array.</param>
        /// <param name="len">The number of bytes.</param>
        /// <param name="recordType">The record type.</param>
        public TlsEncodeResult(byte[] buf, int off, int len, short recordType)
        {
            this.buf = buf;
            this.off = off;
            this.len = len;
            this.recordType = recordType;
        }
    }
}
