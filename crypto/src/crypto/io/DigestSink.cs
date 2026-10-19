using System;
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.IO
{
    /// <summary>A write-only stream that feeds the data written to it into a digest.</summary>
    public sealed class DigestSink
        : BaseOutputStream
    {
        private readonly IDigest m_digest;

        /// <summary>Create a new <see cref="DigestSink"/>.</summary>
        /// <param name="digest">The digest.</param>
        public DigestSink(IDigest digest)
        {
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));
        }

        public IDigest Digest => m_digest;

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count > 0)
            {
                m_digest.BlockUpdate(buffer, offset, count);
            }
        }

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        /// <inheritdoc/>
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return Streams.WriteAsyncDirect(this, buffer, offset, count, cancellationToken);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!buffer.IsEmpty)
            {
                m_digest.BlockUpdate(buffer);
            }
        }

        /// <inheritdoc/>
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return Streams.WriteAsyncDirect(this, buffer, cancellationToken);
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            m_digest.Update(value);
        }
    }
}
