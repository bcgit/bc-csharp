using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Reader for Base64 armored objects - read the headers and then start returning bytes when the data is reached.
    /// </summary>
    /// <remarks>
    /// An IOException is thrown if the CRC check is detected and fails. By default a missing CRC will not cause an
    /// exception. To force CRC detection use <see cref="SetDetectMissingCrc(bool)"/>.
    /// </remarks>
    public class ArmoredInputStream
        : BaseInputStream
    {
        private readonly static byte[] DecodingTable = CreateDecodingTable();

        private static byte[] CreateDecodingTable()
        {
            var decodingTable = new byte[128];
            Arrays.Fill(decodingTable, 0xff);
            for (int i = 'A'; i <= 'Z'; i++)
            {
                decodingTable[i] = (byte)(i - 'A');
            }
            for (int i = 'a'; i <= 'z'; i++)
            {
                decodingTable[i] = (byte)(i - 'a' + 26);
            }
            for (int i = '0'; i <= '9'; i++)
            {
                decodingTable[i] = (byte)(i - '0' + 52);
            }
            decodingTable['+'] = 62;
            decodingTable['/'] = 63;
            return decodingTable;
        }

        /// <summary>Decode the base 64 encoded input data.</summary>
        /// <returns>the offset the data starts in <c>result</c>>.</returns>
        private static int Decode(int in0, int in1, int in2, int in3, byte[] result)
        {
            if (in3 < 0)
                throw new EndOfStreamException("unexpected end of file in armored stream.");

            int b1, b2, b3, b4;
            if (in2 == '=')
            {
                b1 = DecodingTable[in0];
                b2 = DecodingTable[in1];
                if ((b1 | b2) >= 128)
                    throw new ArmoredInputException("invalid armor");

                result[2] = (byte)((b1 << 2) | (b2 >> 4));
                return 2;
            }
            else if (in3 == '=')
            {
                b1 = DecodingTable[in0];
                b2 = DecodingTable[in1];
                b3 = DecodingTable[in2];
                if ((b1 | b2 | b3) >= 128)
                    throw new ArmoredInputException("invalid armor");

                result[1] = (byte)((b1 << 2) | (b2 >> 4));
                result[2] = (byte)((b2 << 4) | (b3 >> 2));
                return 1;
            }
            else
            {
                b1 = DecodingTable[in0];
                b2 = DecodingTable[in1];
                b3 = DecodingTable[in2];
                b4 = DecodingTable[in3];
                if ((b1 | b2 | b3 | b4) >= 128)
                    throw new ArmoredInputException("invalid armor");

                result[0] = (byte)((b1 << 2) | (b2 >> 4));
                result[1] = (byte)((b2 << 4) | (b3 >> 2));
                result[2] = (byte)((b3 << 6) | b4);
                return 0;
            }
        }

        /*
         * Ignore missing CRC checksums.
         * https://tests.sequoia-pgp.org/#ASCII_Armor suggests that missing CRC sums do not invalidate the message.
         */
        private bool m_detectMissingChecksum = false;

        private readonly byte[] m_outBuf = new byte[3];

        private readonly Stream m_input;
        private readonly bool m_hasHeaders;
        private readonly Crc24 m_crc;

        private int m_bufPtr = 3;
        private bool m_crcFound = false;
        private bool m_start = true;
        private string m_header = null;
        private bool m_newLineFound = false;
        private bool m_clearText = false;
        private bool m_restart = false;
        private IList<string> m_headerList = new List<string>();
        private int m_lastC = 0;
        private bool m_isEndOfStream;

        /// <summary>
        /// Create a stream for reading a PGP armored message, parsing up to a header and then reading the data that
        /// follows.
        /// </summary>
        public ArmoredInputStream(Stream input)
            : this(input, hasHeaders: true)
        {
        }

        /// <summary>
        /// Create an armored input stream which will assume the data starts straight away, or parse for headers first
        /// depending on the value of hasHeaders.
        /// </summary>
        /// <param name="input"/>
        /// <param name="hasHeaders"><c>true</c> if headers are to be looked for, <c>false</c> otherwise.</param>
        public ArmoredInputStream(Stream input, bool hasHeaders)
        {
            m_input = input;
            m_hasHeaders = hasHeaders;
            m_crc = new Crc24();

            if (hasHeaders)
            {
                ParseHeaders();
            }

            m_start = false;
        }

        private bool ParseHeaders()
        {
            m_header = null;

            int c;
            int last = 0;
            bool headerFound = false;

            m_headerList = new List<string>();

            //
            // if restart we already have a header
            //
            if (m_restart)
            {
                headerFound = true;
            }
            else
            {
                while ((c = m_input.ReadByte()) >= 0)
                {
                    if (c == '-' && (last == 0 || last == '\n' || last == '\r'))
                    {
                        headerFound = true;
                        break;
                    }

                    last = c;
                }
            }

            if (headerFound)
            {
                bool eolReached = false;
                bool crLf = false;

                MemoryStream buf = new MemoryStream();
                buf.WriteByte((byte)'-');

                if (m_restart)    // we've had to look ahead two '-'
                {
                    buf.WriteByte((byte)'-');
                }

                while ((c = m_input.ReadByte()) >= 0)
                {
                    if (last == '\r' && c == '\n')
                    {
                        crLf = true;
                    }
                    if (eolReached && (last != '\r' && c == '\n'))
                    {
                        break;
                    }
                    if (eolReached && c == '\r')
                    {
                        break;
                    }
                    if (c == '\r' || (last != '\r' && c == '\n'))
                    {
                        string line;
                        try
                        {
                            line = Strings.FromUtf8ByteArray(buf.ToArray());
                        }
                        catch (Exception e)
                        {
                            throw new ArmoredInputException(e.Message);
                        }

                        if (line.Trim().Length < 1)
                            break;

                        if (m_headerList.Count > 0 && line.IndexOf(':') < 0)
                            throw new ArmoredInputException("invalid armor header");

                        m_headerList.Add(line);
                        buf.SetLength(0);
                    }

                    if (c != '\n' && c != '\r')
                    {
                        buf.WriteByte((byte)c);
                        eolReached = false;
                    }
                    else
                    {
                        if (c == '\r' || (last != '\r' && c == '\n'))
                        {
                            eolReached = true;
                        }
                    }

                    last = c;
                }

                if (crLf)
                {
                    int nl = m_input.ReadByte(); // skip last \n
                    if (nl != '\n')
                        throw new ArmoredInputException("inconsistent line endings in headers");
                }
            }

            if (m_headerList.Count > 0)
            {
                m_header = m_headerList[0];
            }

            m_clearText = "-----BEGIN PGP SIGNED MESSAGE-----".Equals(m_header);
            m_newLineFound = true;

            return headerFound;
        }

        /// <returns><c>true</c> if we are inside the clear text section of a PGP signed message.</returns>
        public bool IsClearText() => m_clearText;

        /// <returns><c>true</c> if the stream is actually at end of file.</returns>
        public bool IsEndOfStream() => m_isEndOfStream;

        /// <summary>Return the armor header line (if there is one).</summary>
        /// <returns>the armor header line, <c>null</c> if none present.</returns>
        public string GetArmorHeaderLine() => m_header;

        /// <summary>Return the armor headers (the lines after the armor header line).</summary>
        /// <returns>an array of armor headers, <c>null</c> if there are none.</returns>
        public string[] GetArmorHeaders()
        {
            if (m_headerList.Count <= 1)
                return null;

            string[] hdrs = new string[m_headerList.Count - 1];
            for (int i = 0; i != hdrs.Length; i++)
            {
                hdrs[i] = m_headerList[i + 1];
            }

            return hdrs;
        }

        private int ReadIgnoreSpace()
        {
            int c;
            do
            {
                c = m_input.ReadByte();
            }
            while (c == ' ' || c == '\t' || c == '\f' || c == '\v');

            if (c >= 128)
                throw new ArmoredInputException("invalid armor");

            return c;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            /*
             * TODO Currently can't return partial data when exception thrown (breaking test case), so we don't inherit
             * the base class implementation. Probably the reason is that throws don't mark this instance as 'failed'.
             */
            int pos = 0;
            while (pos < count)
            {
                int b = ReadByte();
                if (b < 0)
                    break;

                buffer[offset + pos++] = (byte)b;
            }
            return pos;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            /*
             * TODO Currently can't return partial data when exception thrown (breaking test case), so we don't inherit
             * the base class implementation. Probably the reason is that throws don't mark this instance as 'failed'.
             */
            int pos = 0;
            while (pos < buffer.Length)
            {
                int b = ReadByte();
                if (b < 0)
                    break;

                buffer[pos++] = (byte)b;
            }
            return pos;
        }
#endif

        public override int ReadByte()
        {
            if (m_start)
            {
                if (m_hasHeaders)
                {
                    ParseHeaders();
                }

                m_crc?.Reset();
                m_start = false;
            }

            int c;

            if (m_clearText)
            {
                c = m_input.ReadByte();

                if (c == '\r' || (c == '\n' && m_lastC != '\r'))
                {
                    m_newLineFound = true;
                }
                else if (m_newLineFound && c == '-')
                {
                    c = m_input.ReadByte();
                    if (c == '-')            // a header, not dash escaped
                    {
                        m_clearText = false;
                        m_start = true;
                        m_restart = true;
                    }
                    else                   // a space - must be a dash escape
                    {
                        c = m_input.ReadByte();
                    }
                    m_newLineFound = false;
                }
                else
                {
                    if (c != '\n' && m_lastC != '\r')
                    {
                        m_newLineFound = false;
                    }
                }

                m_lastC = c;

                if (c < 0)
                {
                    m_isEndOfStream = true;
                }

                return c;
            }

            if (m_bufPtr > 2 || m_crcFound)
            {
                c = ReadIgnoreSpace();

                if (c == '\r' || c == '\n')
                {
                    c = ReadIgnoreSpace();

                    while (c == '\n' || c == '\r')
                    {
                        c = ReadIgnoreSpace();
                    }

                    if (c == '=')            // crc reached
                    {
                        m_bufPtr = Decode(ReadIgnoreSpace(), ReadIgnoreSpace(), ReadIgnoreSpace(), ReadIgnoreSpace(), m_outBuf);
                        if (m_bufPtr != 0)
                            throw new ArmoredInputException("malformed crc in armored message.");

                        m_crcFound = true;

                        if (m_crc != null)
                        {
                            int i = (int)Pack.BE_To_UInt24(m_outBuf);
                            if (i != m_crc.Value)
                                throw new ArmoredInputException("crc check failed in armored message.");
                        }

                        return ReadByte();
                    }

                    if (c == '-')        // end of record reached
                    {
                        while ((c = m_input.ReadByte()) >= 0)
                        {
                            if (c == '\n' || c == '\r')
                                break;
                        }

                        if (!m_crcFound && m_detectMissingChecksum)
                            throw new ArmoredInputException("crc check not found");

                        m_crcFound = false;
                        m_start = true;
                        m_bufPtr = 3;

                        if (c < 0)
                        {
                            m_isEndOfStream = true;
                        }

                        return -1;
                    }
                }

                if (c < 0)
                {
                    m_isEndOfStream = true;
                    return -1;
                }

                m_bufPtr = Decode(c, ReadIgnoreSpace(), ReadIgnoreSpace(), ReadIgnoreSpace(), m_outBuf);

                if (m_crc != null)
                {
                    if (m_bufPtr == 0)
                    {
                        m_crc.Update3(m_outBuf, 0);
                    }
                    else
                    {
                        for (int i = m_bufPtr; i < 3; ++i)
                        {
                            m_crc.Update(m_outBuf[i]);
                        }
                    }
                }
            }

            return (int)m_outBuf[m_bufPtr++];
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_input.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <summary>Change how the stream should react if it encounters a missing CRC checksum.</summary>
        /// <remarks>
        /// The default value is <c>false</c> (ignore missing CRC checksums). If the behavior is set to <c>true</c>, an
        /// <see cref="IOException"/> will be thrown when a missing CRC checksum is encountered.
        /// </remarks>
        /// <param name="detectMissing">ignore missing CRC sums</param>
        public virtual void SetDetectMissingCrc(bool detectMissing)
        {
            m_detectMissingChecksum = detectMissing;
        }
    }
}
