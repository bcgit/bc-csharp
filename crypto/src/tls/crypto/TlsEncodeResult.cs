using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>The result of encoding a record: a buffer region together with the record type.</summary>
    public sealed class TlsEncodeResult
    {
        /// <summary>The buffer holding the encoded record.</summary>
        public readonly byte[] buf;
        /// <summary>The offset into the buffer at which the record starts, and its length.</summary>
        public readonly int off, len;
        /// <summary>The record type of the encoded record.</summary>
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
