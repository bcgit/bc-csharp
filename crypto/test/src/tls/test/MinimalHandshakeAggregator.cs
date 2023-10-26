using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    /**
     * A very minimal and stupid class to aggregate DTLS handshake messages.  Only sufficient for unit tests.
     */
    public class MinimalHandshakeAggregator
        : DatagramTransport
    {
        private readonly DatagramTransport m_transport;

        private readonly bool m_aggregateReceiving, m_aggregateSending;

        private byte[] m_receiveBuf, m_sendBuf;

        private int m_receiveRecordCount, m_sendRecordCount;

        private byte[] AddToBuf(byte[] baseBuf, byte[] buf, int off, int len)
        {
            byte[] ret = new byte[baseBuf.Length + len];
            Array.Copy(baseBuf, 0, ret, 0, baseBuf.Length);
            Array.Copy(buf, off, ret, baseBuf.Length, len);
            return ret;
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        private byte[] AddToBuf(byte[] baseBuf, ReadOnlySpan<byte> buf)
        {
            byte[] ret = new byte[baseBuf.Length + buf.Length];
            Array.Copy(baseBuf, 0, ret, 0, baseBuf.Length);
            buf.CopyTo(ret[baseBuf.Length..]);
            return ret;
        }
#endif

        private void AddToReceiveBuf(byte[] buf, int off, int len)
        {
            m_receiveBuf = AddToBuf(m_receiveBuf, buf, off, len);
            m_receiveRecordCount++;
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        private void AddToReceiveBuf(ReadOnlySpan<byte> buf)
        {
            m_receiveBuf = AddToBuf(m_receiveBuf, buf);
            m_receiveRecordCount++;
        }
#endif

        private void ResetReceiveBuf()
        {
            m_receiveBuf = new byte[0];
            m_receiveRecordCount = 0;
        }

        private void AddToSendBuf(byte[] buf, int off, int len)
        {
            m_sendBuf = AddToBuf(m_sendBuf, buf, off, len);
            m_sendRecordCount++;
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        private void AddToSendBuf(ReadOnlySpan<byte> buf)
        {
            m_sendBuf = AddToBuf(m_sendBuf, buf);
            m_sendRecordCount++;
        }
#endif

        private void ResetSendBuf()
        {
            m_sendBuf = new byte[0];
            m_sendRecordCount = 0;
        }

        /** Whether the buffered aggregated data should be flushed after this packet.
         * This is done on the end of the first flight - ClientHello and ServerHelloDone - and anything that is
         * Epoch 1.
         */
        private bool FlushAfterThisPacket(byte[] buf, int off, int len)
        {
            int epoch = TlsUtilities.ReadUint16(buf, off + 3);
            if (epoch > 0)
                return true;

            short contentType = TlsUtilities.ReadUint8(buf, off);
            if (ContentType.handshake != contentType)
                return false;

            short msgType = TlsUtilities.ReadUint8(buf, off + 13);
            switch (msgType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.server_hello_done:
                return true;
            default:
                return false;
            }
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        private bool FlushAfterThisPacket(ReadOnlySpan<byte> buffer)
        {
            int epoch = TlsUtilities.ReadUint16(buffer[3..]);
            if (epoch > 0)
                return true;

            short contentType = TlsUtilities.ReadUint8(buffer);
            if (ContentType.handshake != contentType)
                return false;

            short msgType = TlsUtilities.ReadUint8(buffer[13..]);
            switch (msgType)
            {
            case HandshakeType.client_hello:
            case HandshakeType.server_hello_done:
                return true;
            default:
                return false;
            }
        }
#endif

        public MinimalHandshakeAggregator(DatagramTransport transport, bool aggregateReceiving, bool aggregateSending)
        {
            m_transport = transport;
            m_aggregateReceiving = aggregateReceiving;
            m_aggregateSending = aggregateSending;

            ResetReceiveBuf();
            ResetSendBuf();
        }

        public virtual int GetReceiveLimit() => m_transport.GetReceiveLimit();

        public virtual int GetSendLimit() => m_transport.GetSendLimit();

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            long endMillis = DateTimeUtilities.CurrentUnixMs() + waitMillis;
            for (;;)
            {
                int length = m_transport.Receive(buf, off, len, waitMillis);
                if (length < 0 || !m_aggregateReceiving)
                    return length;

                AddToReceiveBuf(buf, off, length);

                if (FlushAfterThisPacket(buf, off, length))
                {
                    if (m_receiveRecordCount > 1)
                    {
                        Console.WriteLine("RECEIVING {0} RECORDS IN {1} BYTE PACKET", m_receiveRecordCount, length);
                    }
                    Array.Copy(m_receiveBuf, 0, buf, off, System.Math.Min(len, m_receiveBuf.Length));
                    ResetReceiveBuf();
                    return length;
                }

                long now = DateTimeUtilities.CurrentUnixMs();
                if (now >= endMillis)
                    return -1;

                waitMillis = (int)(endMillis - now);
            }
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            long endMillis = DateTimeUtilities.CurrentUnixMs() + waitMillis;
            for (;;)
            {
                int length = m_transport.Receive(buffer, waitMillis);
                if (length < 0 || !m_aggregateReceiving)
                    return length;

                AddToReceiveBuf(buffer);

                if (FlushAfterThisPacket(buffer))
                {
                    if (m_receiveRecordCount > 1)
                    {
                        Console.WriteLine("RECEIVING {0} RECORDS IN {1} BYTE PACKET", m_receiveRecordCount, length);
                    }
                    int resultLength = System.Math.Min(buffer.Length, m_receiveBuf.Length);
                    m_receiveBuf.AsSpan(0, resultLength).CopyTo(buffer);
                    ResetReceiveBuf();
                    return resultLength;
                }

                long now = DateTimeUtilities.CurrentUnixMs();
                if (now >= endMillis)
                    return -1;

                waitMillis = (int)(endMillis - now);
            }
        }
#endif

        public virtual void Send(byte[] buf, int off, int len)
        {
            if (!m_aggregateSending)
            {
                m_transport.Send(buf, off, len);
                return;
            }
            AddToSendBuf(buf, off, len);

            if (FlushAfterThisPacket(buf, off, len))
            {
                if (m_sendRecordCount > 1)
                {
                    Console.WriteLine("SENDING {0} RECORDS IN {1} BYTE PACKET", m_sendRecordCount, m_sendBuf.Length);
                }
                m_transport.Send(m_sendBuf, 0, m_sendBuf.Length);
                ResetSendBuf();
            }
        }

        //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            if (!m_aggregateSending)
            {
                m_transport.Send(buffer);
                return;
            }
            AddToSendBuf(buffer);

            if (FlushAfterThisPacket(buffer))
            {
                if (m_sendRecordCount > 1)
                {
                    Console.WriteLine("SENDING {0} RECORDS IN {1} BYTE PACKET", m_sendRecordCount, m_sendBuf.Length);
                }
                m_transport.Send(m_sendBuf, 0, m_sendBuf.Length);
                ResetSendBuf();
            }
        }
#endif

        public virtual void Close() => m_transport.Close();
    }
}
