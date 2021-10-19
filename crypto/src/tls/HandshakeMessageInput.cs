using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    // TODO Rewrite without MemoryStream
    public sealed class HandshakeMessageInput
        : MemoryStream
    {
        private readonly int m_offset;

        internal HandshakeMessageInput(byte[] buf, int offset, int length)
#if PORTABLE
            : base(buf, offset, length, false)
#else
            : base(buf, offset, length, false, true)
#endif
        {
#if PORTABLE
            this.m_offset = 0;
#else
            this.m_offset = offset;
#endif
        }

        public void UpdateHash(TlsHash hash)
        {
            Streams.WriteBufTo(this, new TlsHashSink(hash));
        }

        internal void UpdateHashPrefix(TlsHash hash, int bindersSize)
        {
#if PORTABLE
            byte[] buf = ToArray();
            int count = buf.Length;
#else
            byte[] buf = GetBuffer();
            int count = (int)Length;
#endif

            hash.Update(buf, m_offset, count - bindersSize);
        }

        internal void UpdateHashSuffix(TlsHash hash, int bindersSize)
        {
#if PORTABLE
            byte[] buf = ToArray();
            int count = buf.Length;
#else
            byte[] buf = GetBuffer();
            int count = (int)Length;
#endif

            hash.Update(buf, m_offset + count - bindersSize, bindersSize);
        }
    }
}
