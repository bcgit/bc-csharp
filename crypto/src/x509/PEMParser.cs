using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.X509
{
    internal class PemParser
    {
        private readonly string m_header1;
        private readonly string m_header2;
        private readonly string m_footer1;
        private readonly string m_footer2;

        internal PemParser(string type)
        {
            m_header1 = "-----BEGIN " + type + "-----";
            m_header2 = "-----BEGIN X509 " + type + "-----";
            m_footer1 = "-----END " + type + "-----";
            m_footer2 = "-----END X509 " + type + "-----";
        }

        private string ReadLine(Stream inStream)
        {
            StringBuilder buf = new StringBuilder();

            for (;;)
            {
                int c = inStream.ReadByte();
                if (c < 0)
                    return null;

                if (c == '\n' || c == '\r')
                {
                    if (buf.Length > 0)
                        return buf.ToString();
                }
                else
                {
                    buf.Append((char)c);
                }
            }
        }

        internal Asn1Sequence ReadPemObject(Stream inStream)
        {
            string line;
            while ((line = ReadLine(inStream)) != null)
            {
                if (Platform.StartsWith(line, m_header1) || Platform.StartsWith(line, m_header2))
                    break;
            }

            StringBuilder buf = new StringBuilder();
            while ((line = ReadLine(inStream)) != null)
            {
                if (Platform.StartsWith(line, m_footer1) || Platform.StartsWith(line, m_footer2))
                    break;

                buf.Append(line);
            }

            if (buf.Length < 1)
                return null;

            Asn1Object obj = Asn1Object.FromByteArray(Base64.Decode(buf.ToString()));

            if (!(obj is Asn1Sequence seq))
                throw new IOException("malformed PEM data encountered");

            return seq;
        }
    }
}
