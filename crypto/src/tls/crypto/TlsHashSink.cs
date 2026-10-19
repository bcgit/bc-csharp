using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Crypto
{
    public class TlsHashSink
        : BaseOutputStream
    {
        private readonly TlsHash m_hash;

        /// <summary>Create a new <see cref="TlsHashSink"/>.</summary>
        /// <param name="hash">The hash.</param>
        public TlsHashSink(TlsHash hash)
        {
            this.m_hash = hash;
        }

        public virtual TlsHash Hash
        {
            get { return m_hash; }
        }

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count > 0)
            {
                m_hash.Update(buffer, offset, count);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!buffer.IsEmpty)
            {
                m_hash.Update(buffer);
            }
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            m_hash.Update(new byte[]{ value }, 0, 1);
        }
    }
}
