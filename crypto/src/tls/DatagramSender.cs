using System;
using System.IO;

namespace Org.BouncyCastle.Tls
{
    public interface DatagramSender
    {
        /// <exception cref="IOException"/>
        int GetSendLimit();

        /// <exception cref="IOException"/>
        void Send(byte[] buf, int off, int len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        void Send(ReadOnlySpan<byte> buffer);
#endif
    }
}
