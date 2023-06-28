using System;
using System.IO;

namespace Org.BouncyCastle.Tls
{
    public interface DatagramReceiver
    {
        /// <exception cref="IOException"/>
        int GetReceiveLimit();

        /// <exception cref="IOException"/>
        int Receive(byte[] buf, int off, int len, int waitMillis);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        int Receive(Span<byte> buffer, int waitMillis);
#endif
    }
}
