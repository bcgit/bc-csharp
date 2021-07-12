using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    public sealed class HandshakeMessageInput
        : MemoryStream
    {
        internal HandshakeMessageInput(byte[] buf, int offset, int length)
            : base(buf, offset, length, false)
        {
        }

        public void UpdateHash(TlsHash hash)
        {
            Streams.WriteBufTo(this, new TlsHashSink(hash));
        }
    }
}
