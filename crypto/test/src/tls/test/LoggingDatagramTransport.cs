using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    public class LoggingDatagramTransport
        : DatagramTransport
    {
        private static readonly string HEX_CHARS = "0123456789ABCDEF";

        private readonly DatagramTransport m_transport;
        private readonly TextWriter m_output;
        private readonly long m_launchTimestamp;

        public LoggingDatagramTransport(DatagramTransport transport, TextWriter output)
        {
            this.m_transport = transport;
            this.m_output = output;
            this.m_launchTimestamp = DateTimeUtilities.CurrentUnixMs();
        }

        public virtual int GetReceiveLimit()
        {
            return m_transport.GetReceiveLimit();
        }

        public virtual int GetSendLimit()
        {
            return m_transport.GetSendLimit();
        }

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
            return Receive(buf.AsSpan(off, len), waitMillis);
#else
            int length = m_transport.Receive(buf, off, len, waitMillis);
            if (length >= 0)
            {
                DumpDatagram("Received", buf, off, length);
            }
            return length;
#endif
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            int length = m_transport.Receive(buffer, waitMillis);
            if (length >= 0)
            {
                DumpDatagram("Received", buffer[..length]);
            }
            return length;
        }
#endif

        public virtual void Send(byte[] buf, int off, int len)
        {
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
            Send(buf.AsSpan(off, len));
#else
            DumpDatagram("Sending", buf, off, len);
            m_transport.Send(buf, off, len);
#endif
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            DumpDatagram("Sending", buffer);
            m_transport.Send(buffer);
        }
#endif

        public virtual void Close()
        {
            m_transport.Close();
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        private void DumpDatagram(string verb, ReadOnlySpan<byte> buffer)
        {
            int len = buffer.Length;
            long timestamp = DateTimeUtilities.CurrentUnixMs() - m_launchTimestamp;
            StringBuilder sb = new StringBuilder("(+" + timestamp + "ms) " + verb + " " + len + " byte datagram:");
            for (int pos = 0; pos < len; ++pos)
            {
                if (pos % 16 == 0)
                {
                    sb.Append(Environment.NewLine);
                    sb.Append("    ");
                }
                else if (pos % 16 == 8)
                {
                    sb.Append('-');
                }
                else
                {
                    sb.Append(' ');
                }
                int val = buffer[pos] & 0xFF;
                sb.Append(HEX_CHARS[val >> 4]);
                sb.Append(HEX_CHARS[val & 0xF]);
            }
            Dump(sb.ToString());
        }
#else
        private void DumpDatagram(string verb, byte[] buf, int off, int len)
        {
            long timestamp = DateTimeUtilities.CurrentUnixMs() - m_launchTimestamp;
            StringBuilder sb = new StringBuilder("(+" + timestamp + "ms) " + verb + " " + len + " byte datagram:");
            for (int pos = 0; pos < len; ++pos)
            {
                if (pos % 16 == 0)
                {
                    sb.Append(Environment.NewLine);
                    sb.Append("    ");
                }
                else if (pos % 16 == 8)
                {
                    sb.Append('-');
                }
                else
                {
                    sb.Append(' ');
                }
                int val = buf[off + pos] & 0xFF;
                sb.Append(HEX_CHARS[val >> 4]);
                sb.Append(HEX_CHARS[val & 0xF]);
            }
            Dump(sb.ToString());
        }
#endif

        private void Dump(string s)
        {
            lock (this) m_output.WriteLine(s);
        }
    }
}
