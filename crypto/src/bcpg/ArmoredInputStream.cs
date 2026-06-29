using System;
using System.Collections.Generic;
using System.IO;

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
    /// exception. To force CRC detection use <see cref="Builder.SetDetectMissingCrc(bool)"/>.
    /// <para>
    /// By default a cleartext-signed(CSF) message whose payload contains a malformed dash - prefixed line(a leading
    /// dash that is neither a "-----" armor header nor a "- " dash-escape, contrary to RFC 4880 7.1) is rejected with
    /// an <see cref="ArmoredInputException"/>. Use <see cref="Builder.SetRejectPrefixedDashesInCsfMessages(bool)"/> to
    /// relax this.
    /// </para>
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
        private bool m_detectMissingCrc = false;

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
        private int m_lookAhead = -1;
        private bool m_isEndOfStream;

        private readonly bool m_validateAllowedHeaders;
        private readonly bool m_csfRejectPrefixedDashes;
        private readonly List<string> m_allowedHeaders;

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
            m_validateAllowedHeaders = false;
            m_csfRejectPrefixedDashes = true;
            m_allowedHeaders = DefaultAllowedHeaders();

            if (m_hasHeaders)
            {
                ParseHeaders();
            }

            m_start = false;
        }

        private ArmoredInputStream(Stream input, Builder builder)
        {
            m_input = input;
            m_hasHeaders = builder.m_hasHeaders;
            m_detectMissingCrc = builder.m_detectMissingCrc;
            m_crc = builder.m_ignoreCrc ? null : new Crc24();
            m_validateAllowedHeaders = builder.m_validateAllowedHeaders;
            m_csfRejectPrefixedDashes = builder.m_csfRejectPrefixedDashes;
            m_allowedHeaders = builder.m_allowedHeaders;

            if (m_hasHeaders)
            {
                ParseHeaders();
            }

            if (m_validateAllowedHeaders)
            {
                RejectUnknownHeadersInCsfMessages();
            }

            m_start = false;
        }

        private void RejectUnknownHeadersInCsfMessages()
        {
            var headerLines = m_headerList.GetEnumerator();
            if (!headerLines.MoveNext())
                throw new InvalidOperationException();

            string header = headerLines.Current;

            // Only reject unknown headers in cleartext signed messages
            if (!header.StartsWith("-----BEGIN PGP SIGNED MESSAGE-----"))
                return;

            while (headerLines.MoveNext())
            {
                string headerLine = headerLines.Current;
                if (RejectHeaderLine(m_allowedHeaders, headerLine))
                    throw new ArmoredInputException(
                        $"Illegal ASCII armor header line in clearsigned message encountered: {headerLine}");
            }
        }

        private static bool RejectHeaderLine(List<string> allowedHeaders, string headerLine)
        {
            foreach (string allowedHeader in allowedHeaders)
            {
                if (Platform.StartsWith(headerLine, allowedHeader + ": "))
                    return false;
            }
            return true;
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
                if (m_lookAhead >= 0)
                {
                    // Replay a byte read past while resolving a line-leading dash (see the
                    // malformed branch below). Fall through so it still updates newLineFound /
                    // lastC rather than being returned blind - otherwise a pushed-back '\n'
                    // would not be recognised as a line start and the next armor boundary
                    // would be consumed as clear text.
                    c = m_lookAhead;
                    m_lookAhead = -1;
                }
                else
                {
                    c = m_input.ReadByte();
                }

                if (c == '\r' || (c == '\n' && m_lastC != '\r'))
                {
                    m_newLineFound = true;
                }
                else if (m_newLineFound && c == '-')
                {
                    int next = m_input.ReadByte();
                    if (next == '-') // a header, not dash escaped
                    {
                        m_clearText = false;
                        m_start = true;
                        m_restart = true;
                    }
                    else if (next == ' ') // a space - drop the "- " dash escape
                    {
                        c = m_input.ReadByte();
                    }
                    else
                    {
                        // RFC 4880 7.1: in dash-escaped text every line beginning with a dash
                        // is prefixed with "- "; a leading dash that is neither a "--" header
                        // nor a "- " escape means the message is malformed.
                        if (m_csfRejectPrefixedDashes)
                            throw new ArmoredInputException
                                ("Prefixed dash without trailing space encountered. CSF-signed message malformed.");

                        // Lenient: surface the bytes verbatim rather than silently dropping the
                        // dash. Return the dash now and replay 'next' on the following ReadByte() so
                        // a signature check over the recovered text fails instead of passing.
                        m_lookAhead = next;
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

                        if (!m_crcFound && m_detectMissingCrc)
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
        [Obsolete("Configure via 'Build()' instead")]
        public virtual void SetDetectMissingCrc(bool detectMissing)
        {
            m_detectMissingCrc = detectMissing;
        }

        private static List<string> DefaultAllowedHeaders() => new List<string>(){
            ArmoredOutputStream.HeaderComment,
            ArmoredOutputStream.HeaderVersion,
            ArmoredOutputStream.HeaderCharset,
            ArmoredOutputStream.HeaderHash,
            ArmoredOutputStream.HeaderMessageID,
        };

        public static Builder Build() => new Builder();

        public sealed class Builder
        {
            internal bool m_hasHeaders = true;
            internal bool m_detectMissingCrc = false;
            internal bool m_ignoreCrc = false;
            internal bool m_validateAllowedHeaders = false;
            internal bool m_csfRejectPrefixedDashes = true;
            internal List<string> m_allowedHeaders = DefaultAllowedHeaders();

            internal Builder()
            {
            }

            /// <summary>Enable or disable header parsing (default value <c>true</c>).</summary>
            /// <param name="hasHeaders"><c>true</c> if headers should be expected, <c>false</c> otherwise.</param>
            /// <returns>the current <see cref="Builder"/> instance.</returns>
            public Builder SetParseForHeaders(bool hasHeaders)
            {
                m_hasHeaders = hasHeaders;
                return this;
            }

            /// <returns>the current <see cref="Builder"/> instance.</returns>
            public Builder SetValidateClearsignedMessageHeaders(bool validateAllowedHeaders)
            {
                m_validateAllowedHeaders = validateAllowedHeaders;
                return this;
            }

            /// <summary>
            /// Configure how a cleartext-signed (CSF) message is handled when a payload line begins with a dash that is
            /// neither a "-----" armor header nor a "- " dash-escape.
            /// </summary>
            /// <remarks>
            /// RFC 4880 7.1 requires every cleartext line beginning with a dash to be prefixed with "- " (dash, space),
            /// so a leading dash not followed by a space signals a malformed message. Historically the two leading
            /// characters were dropped unconditionally, so a signature over "payload" also verified against a tampered
            /// "-Xpayload" line.
            /// <para>
            /// Defaults to <c>true</c> (reject with an <see cref="ArmoredInputException"/>). RFC-conformant messages -
            /// including everything written by <see cref="ArmoredOutputStream"/> - never trigger this. When set to
            /// <c>false</c> the offending bytes are returned verbatim instead of being dropped, so a signature check
            /// over the recovered text fails rather than silently succeeding.
            /// </para>
            /// </remarks>
            /// <param name="rejectDashes"><c>true</c> to reject malformed dsah-prefixed CSF messages, <c>false</c> to
            /// surface their bytes verbatim.</param>
            /// <returns>the current <see cref="Builder"/> instance.</returns>
            public Builder SetRejectPrefixedDashesInCsfMessages(bool rejectDashes)
            {
                m_csfRejectPrefixedDashes = rejectDashes;
                return this;
            }

            /// <returns>the current <see cref="Builder"/> instance.</returns>
            public Builder AddAllowedArmorHeader(string header)
            {
                header = header.Trim();
                if (header.Length > 0)
                {
                    m_allowedHeaders.Add(header);
                }
                return this;
            }

            /// <summary>Change how the stream should react if it encounters a missing CRC checksum.</summary>
            /// <remarks>
            /// The default value is <c>false</c> (ignore missing CRC checksums). If the behavior is set to <c>true</c>,
            /// an <see cref="IOException"/> will be thrown when a missing CRC checksum is encountered.
            /// </remarks>
            /// <param name="detectMissingCrc">
            /// <c>false</c> if ignore missing CRC sums, <c>true</c> for exception.
            /// </param>
            /// <returns>the current <see cref="Builder"/> instance.</returns>
            public Builder SetDetectMissingCrc(bool detectMissingCrc)
            {
                m_detectMissingCrc = detectMissingCrc;
                return this;
            }

            /// <summary>
            /// Specifically ignore the CRC if in place (this will also avoid the cost of calculation).
            /// </summary>
            /// <paramref name="ignoreCrc"><c>true</c> if CRC should be ignored, false otherwise.</paramref>
            /// <returns>the current <see cref="Builder"/> instance.</returns>
            public Builder setIgnoreCrc(bool ignoreCrc)
            {
                m_ignoreCrc = ignoreCrc;
                return this;
            }

            public ArmoredInputStream Build(Stream input) => new ArmoredInputStream(input, this);
        }
    }
}
