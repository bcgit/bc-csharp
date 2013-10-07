using System.Text;
using Org.BouncyCastle.Utilities.Date;
using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls.Test
{
    public class LoggingDatagramTransport : DatagramTransport
    {
        private static readonly string HEX_CHARS = "0123456789ABCDEF";

        private readonly DatagramTransport transport;
        private readonly long launchTimestamp;
        private readonly TextWriter output;

        public LoggingDatagramTransport(DatagramTransport transport, TextWriter output)
        {
            this.transport = transport;
            this.output = output;
            this.launchTimestamp = DateTimeUtilities.CurrentUnixMs();
        }

        public int ReceiveLimit
        {
            get
            {
                return transport.ReceiveLimit;
            }
        }

        public int SendLimit
        {
            get
            {
                return transport.SendLimit;
            }
        }        

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            int length = transport.Receive(buf, off, len, waitMillis);
            if (length >= 0)
            {
                dumpDatagram("Received", buf, off, length);
            }
            return length;
        }

        public void Send(byte[] buf, int off, int len)
        {
            dumpDatagram("Sending", buf, off, len);
            transport.Send(buf, off, len);
        }

        public void Close()
        {

        }

        void IDisposable.Dispose()
        {
            Close();
        }

        private void dumpDatagram(string verb, byte[] buf, int off, int len)
        {
            long timestamp = DateTimeUtilities.CurrentUnixMs() - launchTimestamp;
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
            dump(sb.ToString());
        }

        private void dump(String s)
        {
            output.WriteLine(s);
        }
    }
}