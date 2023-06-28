using System;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    public sealed class MacSink
        : BaseOutputStream
    {
        private readonly IMac m_mac;

        public MacSink(IMac mac)
        {
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        public IMac Mac => m_mac;

        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count > 0)
            {
                m_mac.BlockUpdate(buffer, offset, count);
            }
        }

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return Streams.WriteAsyncDirect(this, buffer, offset, count, cancellationToken);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!buffer.IsEmpty)
            {
                m_mac.BlockUpdate(buffer);
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsyncDirect(this, buffer, cancellationToken);
        }
#endif

        public override void WriteByte(byte value)
        {
            m_mac.Update(value);
        }
    }
}
