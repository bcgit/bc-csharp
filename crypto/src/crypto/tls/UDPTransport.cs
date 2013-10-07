using System.Net.Sockets;
using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class UDPTransport : DatagramTransport
    {
        protected const int MIN_IP_OVERHEAD = 20;
        protected const int MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64;
        protected const int UDP_OVERHEAD = 8;

        protected readonly Socket socket;
        protected readonly int receiveLimit, sendLimit;

        public UDPTransport(Socket socket, int mtu)
        {
            if (!socket.IsBound || !socket.Connected)
            {
                throw new ArgumentException("'socket' must be bound and connected");
            }

            this.socket = socket;

            // NOTE: As of JDK 1.6, can use NetworkInterface.getMTU

            this.receiveLimit = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD;
            this.sendLimit = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD;
        }

        public int ReceiveLimit
        {
            get
            {
                return receiveLimit;
            }
        }

        public int SendLimit
        {
            get
            {
                // TODO[DTLS] Implement Path-MTU discovery?
                return sendLimit;
            }
        }

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            socket.ReceiveTimeout = waitMillis;
            return socket.Receive(buf, off, len, SocketFlags.None);
        }

        public void Send(byte[] buf, int off, int len)
        {
            if (len > SendLimit)
            {
                /*
                 * RFC 4347 4.1.1. "If the application attempts to send a record larger than the MTU,
                 * the DTLS implementation SHOULD generate an error, thus avoiding sending a packet
                 * which will be fragmented."
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            socket.Send(buf, off, len, SocketFlags.None);
        }

        public void Close()
        {
            socket.Close();
        }

        void IDisposable.Dispose()
        {
            Close();
        }
    }

}