using System;
using System.Collections.Generic;
using System.Threading;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    public class MockDatagramAssociation
    {
        private readonly int m_mtu;
        private readonly MockDatagramTransport m_client, m_server;

        public MockDatagramAssociation(int mtu)
        {
            m_mtu = mtu;

            var clientQueue = new List<byte[]>();
            var serverQueue = new List<byte[]>();

            m_client = new MockDatagramTransport(this, clientQueue, serverQueue);
            m_server = new MockDatagramTransport(this, serverQueue, clientQueue);
        }

        public virtual int Mtu => m_mtu;

        public virtual DatagramTransport Client => m_client;

        public virtual DatagramTransport Server => m_server;

        private class MockDatagramTransport
            : DatagramTransport
        {
            private readonly MockDatagramAssociation m_outer;
            private readonly IList<byte[]> m_receiveQueue, m_sendQueue;

            internal MockDatagramTransport(MockDatagramAssociation outer, IList<byte[]> receiveQueue,
                IList<byte[]> sendQueue)
            {
                m_outer = outer;
                m_receiveQueue = receiveQueue;
                m_sendQueue = sendQueue;
            }

            public virtual int GetReceiveLimit() => m_outer.Mtu;

            public virtual int GetSendLimit() => m_outer.Mtu;

            public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
            {
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
                return Receive(buf.AsSpan(off, len), waitMillis);
#else
                lock (m_receiveQueue)
                {
                    if (m_receiveQueue.Count < 1)
                    {
                        try
                        {
                            Monitor.Wait(m_receiveQueue, waitMillis);
                        }
                        catch (ThreadInterruptedException)
                        {
                            // TODO Keep waiting until full wait expired?
                        }

                        if (m_receiveQueue.Count < 1)
                            return -1;
                    }

                    byte[] packet = m_receiveQueue[0];
                    m_receiveQueue.RemoveAt(0);
                    int copyLength = System.Math.Min(len, packet.Length);
                    Array.Copy(packet, 0, buf, off, copyLength);
                    return copyLength;
                }
#endif
            }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
            public virtual int Receive(Span<byte> buffer, int waitMillis)
            {
                lock (m_receiveQueue)
                {
                    if (m_receiveQueue.Count < 1)
                    {
                        try
                        {
                            Monitor.Wait(m_receiveQueue, waitMillis);
                        }
                        catch (ThreadInterruptedException)
                        {
                            // TODO Keep waiting until full wait expired?
                        }

                        if (m_receiveQueue.Count < 1)
                            return -1;
                    }

                    byte[] packet = m_receiveQueue[0];
                    m_receiveQueue.RemoveAt(0);
                    int copyLength = System.Math.Min(buffer.Length, packet.Length);
                    packet.AsSpan(0, copyLength).CopyTo(buffer);
                    return copyLength;
                }
            }
#endif

            public virtual void Send(byte[] buf, int off, int len)
            {
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
                Send(buf.AsSpan(off, len));
#else
                if (len > m_outer.Mtu)
                {
                    // TODO Simulate rejection?
                }

                byte[] packet = Arrays.CopyOfRange(buf, off, off + len);

                lock (m_sendQueue)
                {
                    m_sendQueue.Add(packet);
                    Monitor.PulseAll(m_sendQueue);
                }
#endif
            }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
            public virtual void Send(ReadOnlySpan<byte> buffer)
            {
                if (buffer.Length > m_outer.Mtu)
                {
                    // TODO Simulate rejection?
                }

                byte[] packet = buffer.ToArray();

                lock (m_sendQueue)
                {
                    m_sendQueue.Add(packet);
                    Monitor.PulseAll(m_sendQueue);
                }
            }
#endif

            public virtual void Close()
            {
                // TODO?
            }
        }
    }
}
