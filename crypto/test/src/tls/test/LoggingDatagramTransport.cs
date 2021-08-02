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
            int length = m_transport.Receive(buf, off, len, waitMillis);
            if (length >= 0)
            {
                DumpDatagram("Received", buf, off, length);
            }
            return length;
        }

        public virtual void Send(byte[] buf, int off, int len)
        {
            DumpDatagram("Sending", buf, off, len);
            m_transport.Send(buf, off, len);
        }

        public virtual void Close()
        {
            m_transport.Close();
        }

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

        private void Dump(string s)
        {
            lock (this) m_output.WriteLine(s);
        }
    }
}
