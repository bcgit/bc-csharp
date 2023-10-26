using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    public class FilteredDatagramTransport
        : DatagramTransport
    {
        public delegate bool FilterPredicate(byte[] buf, int off, int len);

        public static bool AlwaysAllow(byte[] buf, int off, int len) => true;

        private readonly DatagramTransport m_transport;

        private readonly FilterPredicate m_allowReceiving, m_allowSending;

        public FilteredDatagramTransport(DatagramTransport transport, FilterPredicate allowReceiving,
            FilterPredicate allowSending)
        {
            m_transport = transport;
            m_allowReceiving = allowReceiving;
            m_allowSending = allowSending;
        }

        public virtual int GetReceiveLimit() => m_transport.GetReceiveLimit();

        public virtual int GetSendLimit() => m_transport.GetSendLimit();

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            long endMillis = DateTimeUtilities.CurrentUnixMs() + waitMillis;
            for (;;)
            {
                int length = m_transport.Receive(buf, off, len, waitMillis);
                if (length < 0 || m_allowReceiving(buf, off, len))
                    return length;

                Console.WriteLine("PACKET FILTERED ({0} byte packet not received)", length);

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
                if (length < 0 || m_allowReceiving(buffer.ToArray(), 0, buffer.Length))
                    return length;

                Console.WriteLine("PACKET FILTERED ({0} byte packet not received)", length);

                long now = DateTimeUtilities.CurrentUnixMs();
                if (now >= endMillis)
                    return -1;

                waitMillis = (int)(endMillis - now);
            }
        }
#endif

        public virtual void Send(byte[] buf, int off, int len)
        {
            if (!m_allowSending(buf, off, len))
            {
                Console.WriteLine("PACKET FILTERED ({0} byte packet not sent)", len);
            }
            else
            {
                m_transport.Send(buf, off, len);
            }
        }

        //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            if (!m_allowSending(buffer.ToArray(), 0, buffer.Length))
            {
                Console.WriteLine("PACKET FILTERED ({0} byte packet not sent)", buffer.Length);
            }
            else
            {
                m_transport.Send(buffer);
            }
        }
#endif

        public virtual void Close() => m_transport.Close();

        //static FilterPredicate ALWAYS_ALLOW = new FilterPredicate() {
        //    @Override
        //    public boolean allowPacket(byte[] buf, int off, int len)
        //    {
        //        return true;
        //    }
        //};

        //interface FilterPredicate {
        //    boolean allowPacket(byte[] buf, int off, int len);
        //}
    }
}
