#nullable enable

using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers;
#endif
using System.Threading;

namespace Org.BouncyCastle.Tls.Crypto
{
    public struct TlsEncodeResult: IDisposable
    {
        public byte[] buf;
        public readonly int off, len;
        public readonly short recordType;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public readonly ArrayPool<byte>? pool;
#endif

        public TlsEncodeResult(byte[] buf, int off, int len, short recordType
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            , ArrayPool<byte>? pool = null
#endif
            ) {
            this.buf = buf;
            this.off = off;
            this.len = len;
            this.recordType = recordType;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            this.pool = pool;
#endif
        }

        public void Dispose()
        {
            byte[]? killBuf = Interlocked.Exchange(ref this.buf, null!);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (killBuf is not null)
            {
                this.pool?.Return(killBuf);
            }
#endif
        }
    }
}
