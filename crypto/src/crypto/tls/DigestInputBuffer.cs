using System;
using System.IO;

using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    internal class DigestInputBuffer
        :   MemoryStream
    {
        internal void UpdateDigest(IDigest d)
        {
            Streams.WriteBufTo(this, new DigestSink(d));
        }
    }
}
