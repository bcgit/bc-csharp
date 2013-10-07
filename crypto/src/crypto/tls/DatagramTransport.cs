using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    public interface DatagramTransport : IDisposable
    {
        int ReceiveLimit { get; }

        int SendLimit { get; }

        int Receive(byte[] buf, int off, int len, int waitMillis);

        void Send(byte[] buf, int off, int len);

        void Close();
    }
}