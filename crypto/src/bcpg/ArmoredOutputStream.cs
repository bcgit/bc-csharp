using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Output stream that writes data in ASCII Armored format.</summary>
    /// <remarks>
    /// <para>
    /// Note 1: An instance of <see cref="ArmoredOutputStream"/> needs to be <see cref="IDisposable">disposed</see> (or
    /// closed) to write the final checksum. <see cref="Stream.Flush">Flushing</see> will not do this as other classes
    /// assume it is always fine to call <see cref="Stream.Flush"/> - it is not though if the checksum gets output.
    /// </para>
    /// <para>
    /// Note 2: As multiple PGP blobs are often written to the same stream, <see cref="IDisposable">disposing</see> (or
    /// closing) does not dispose/close the underlying stream.
    /// </para>
    /// </remarks>
    public class ArmoredOutputStream
        : BaseOutputStream
    {
        public static readonly string HeaderCharset = "Charset";
        public static readonly string HeaderComment = "Comment";
        public static readonly string HeaderHash = "Hash";
        public static readonly string HeaderMessageID = "MessageID";
        public static readonly string HeaderVersion = "Version";

        private static readonly string NewLine = Environment.NewLine;
        private static readonly string HeaderStart = "-----BEGIN PGP ";
        private static readonly string HeaderTail = "-----";
        private static readonly string FooterStart = "-----END PGP ";
        private static readonly string FooterTail = "-----";

        private static readonly byte[] EncodingTable =
        {
            (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
            (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
            (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
            (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v',
            (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6',
            (byte)'7', (byte)'8', (byte)'9',
            (byte)'+', (byte)'/'
        };

        private static readonly string Version = CreateVersion();
        private static string CreateVersion()
        {
            var assembly = Assembly.GetExecutingAssembly();

            var titleAttr = assembly.GetCustomAttribute<AssemblyTitleAttribute>();
            var versionAttr = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();

            if (titleAttr == null || versionAttr == null)
                return "BouncyCastle (unknown version)";

            return titleAttr.Title + " v" + versionAttr.InformationalVersion;
        }

        /// <summary>Encode the input data producing a base 64 encoded byte array.</summary>
        private static void Encode(Stream outStream, byte[] data, int len)
        {
            Debug.Assert(len > 0);
            Debug.Assert(len < 4);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bs = stackalloc byte[4];
#else
            byte[] bs = new byte[4];
#endif

            int d1 = data[0];
            bs[0] = EncodingTable[(d1 >> 2) & 0x3f];

            switch (len)
            {
            case 1:
            {
                bs[1] = EncodingTable[(d1 << 4) & 0x3f];
                bs[2] = (byte)'=';
                bs[3] = (byte)'=';
                break;
            }
            case 2:
            {
                int d2 = data[1];
                bs[1] = EncodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
                bs[2] = EncodingTable[(d2 << 2) & 0x3f];
                bs[3] = (byte)'=';
                break;
            }
            case 3:
            {
                int d2 = data[1];
                int d3 = data[2];
                bs[1] = EncodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
                bs[2] = EncodingTable[((d2 << 2) | (d3 >> 6)) & 0x3f];
                bs[3] = EncodingTable[d3 & 0x3f];
                break;
            }
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            outStream.Write(bs);
#else
            outStream.Write(bs, 0, bs.Length);
#endif
        }

        /// <summary>Encode the input data producing a base 64 encoded byte array.</summary>
        private static void Encode3(Stream outStream, byte[] data)
        {
            int d1 = data[0];
            int d2 = data[1];
            int d3 = data[2];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bs = stackalloc byte[4];
#else
            byte[] bs = new byte[4];
#endif

            bs[0] = EncodingTable[(d1 >> 2) & 0x3f];
            bs[1] = EncodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
            bs[2] = EncodingTable[((d2 << 2) | (d3 >> 6)) & 0x3f];
            bs[3] = EncodingTable[d3 & 0x3f];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            outStream.Write(bs);
#else
            outStream.Write(bs, 0, bs.Length);
#endif
        }

        private readonly Stream m_outStream;
        private byte[] buf = new byte[3];
        private int bufPtr = 0;
        private Crc24 crc = new Crc24();
        private int chunkCount = 0;
        private int lastb;

        private bool start = true;
        private bool clearText = false;
        private bool newLine = false;

        private string type;
        private readonly Dictionary<string, List<string>> m_headers;

        public ArmoredOutputStream(Stream outStream)
            : this(outStream, true)
        {
        }

        public ArmoredOutputStream(Stream outStream, bool addVersionHeader)
        {
            m_outStream = outStream;
            m_headers = new Dictionary<string, List<string>>();

            if (addVersionHeader)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                SetHeader(HeaderVersion, Version);
#pragma warning restore CS0618 // Type or member is obsolete
            }
        }

        public ArmoredOutputStream(Stream outStream, IDictionary<string, string> headers)
            : this(outStream, headers, true)
        {
        }

        public ArmoredOutputStream(Stream outStream, IDictionary<string, string> headers, bool addVersionHeader)
            : this(outStream, addVersionHeader && !headers.ContainsKey(HeaderVersion))
        {
            foreach (var header in headers)
            {
                m_headers.Add(header.Key, new List<string>{ header.Value });
            }
        }

        internal ArmoredOutputStream(Stream outStream, Builder builder)
            : this(outStream)
        {
            if (!builder.m_computeCrcSum)
            {
                crc = null;
            }

            m_headers.Clear();
            foreach (var header in builder.m_headers)
            {
                m_headers[header.Key] = header.Value;
            }
        }

        /// <summmary>Set an additional header entry.</summmary>
        /// <remarks>
        /// Any current value(s) under the same name will be replaced by the new one. A <c>null</c> value will clear the
        /// named entry.
        /// </remarks>
        /// <param name="name">the name of the header entry.</param>
        /// <param name="val">the value of the header entry.</param>
        [Obsolete("Configure via 'Build()' instead")]
        public void SetHeader(string name, string val)
        {
            if (val == null)
            {
                m_headers.Remove(name);
                return;
            }

            if (m_headers.TryGetValue(name, out var valueList))
            {
                valueList.Clear();
            }
            else
            {
                valueList = new List<string>(1);
                m_headers[name] = valueList;
            }

            valueList.Add(val);
        }

        /// <summary>Set an additional header entry. The current value(s) will continue to exist together with the new
        /// one. Adding a <c>null</c> value has no effect.</summary>
        /// <param name="name">the name of the header entry.</param>
        /// <param name="val">the value of the header entry.</param>
        [Obsolete("Configure via 'Build()' instead")]
        public void AddHeader(string name, string val)
        {
            if (val == null || name == null)
                return;

            if (!m_headers.TryGetValue(name, out var valueList))
            {
                valueList = new List<string>(1);
                m_headers[name] = valueList;
            }

            valueList.Add(val);
        }

        /// <summary>Reset the headers to only contain a Version string (if one is present).</summary>
        [Obsolete("Configure via 'Build()' instead")]
        public void ResetHeaders()
        {
            bool hadVersion = m_headers.TryGetValue(HeaderVersion, out var version);

            m_headers.Clear();

            if (hadVersion)
            {
                m_headers.Add(HeaderVersion, version);
            }
        }

        /// <summary>Start a clear text signed message - backwards compatibility.</summary>
        public void BeginClearText(HashAlgorithmTag hashAlgorithm) =>
            BeginClearText(new HashAlgorithmTag[]{ hashAlgorithm });

        public void BeginClearText(params HashAlgorithmTag[] hashAlgorithms)
        {
            StringBuilder sb = new StringBuilder("-----BEGIN PGP SIGNED MESSAGE-----");
            sb.Append(NewLine);
            foreach (HashAlgorithmTag hashAlgorithm in hashAlgorithms)
            {
                string hash;
                switch (hashAlgorithm)
                {
                case HashAlgorithmTag.MD5:
                    hash = "MD5";
                    break;
                case HashAlgorithmTag.Sha1:
                    hash = "SHA1";
                    break;
                case HashAlgorithmTag.RipeMD160:
                    hash = "RIPEMD160";
                    break;
                case HashAlgorithmTag.MD2:
                    hash = "MD2";
                    break;
                case HashAlgorithmTag.Sha256:
                    hash = "SHA256";
                    break;
                case HashAlgorithmTag.Sha384:
                    hash = "SHA384";
                    break;
                case HashAlgorithmTag.Sha512:
                    hash = "SHA512";
                    break;
                case HashAlgorithmTag.Sha224:
                    hash = "SHA224";
                    break;
#pragma warning disable CS0618 // Type or member is obsolete
                case HashAlgorithmTag.Sha3_256:
                case HashAlgorithmTag.Sha3_256_Old:
                    hash = "SHA3-256";
                    break;
                case HashAlgorithmTag.Sha3_384:
                    hash = "SHA3-384";
                    break;
                case HashAlgorithmTag.Sha3_512:
                case HashAlgorithmTag.Sha3_512_Old:
                    hash = "SHA3-512";
                    break;
                case HashAlgorithmTag.Sha3_224:
                    hash = "SHA3-224";
                    break;
#pragma warning restore CS0618 // Type or member is obsolete
                default:
                    throw new IOException("unknown hash algorithm tag in beginClearText: " + hashAlgorithm);
                }
                sb.Append(HeaderHash).Append(": ").AppendLine(hash);
            }
            sb.AppendLine();

            DoWrite(sb.ToString());

            clearText = true;
            newLine = true;
            lastb = 0;
        }

        public void EndClearText()
        {
            clearText = false;
        }

        private void WriteHeaderEntry(string name, string val)
        {
            // Single chokepoint for every header-setting path (deprecated setHeader/addHeader, the
            // Hashtable constructor and the Builder). A CR or LF in a name or value would inject extra
            // armor header lines, and a blank line would terminate the header block early with the rest
            // parsed as base64 body -- an armor header injection. Reject it here so no path can forge it.
            if (HasLineBreak(name) || HasLineBreak(val))
                throw new ArgumentException("armor header must not contain CR/LF");

            DoWrite(name);
            DoWrite(": ");
            DoWrite(val);
            DoWrite(NewLine);
        }

        private static bool HasLineBreak(string s)
        {
            return s != null && (s.IndexOf('\r') >= 0 || s.IndexOf('\n') >= 0);
        }

        public override void WriteByte(byte value)
        {
            if (clearText)
            {
                m_outStream.WriteByte(value);

                if (newLine)
                {
                    if (!(value == '\n' && lastb == '\r'))
                    {
                        newLine = false;
                    }
                    if (value == '-')
                    {
                        m_outStream.WriteByte((byte)' ');
                        m_outStream.WriteByte((byte)'-');      // dash escape
                    }
                }
                if (value == '\r' || (value == '\n' && lastb != '\r'))
                {
                    newLine = true;
                }
                lastb = value;
                return;
            }

            if (start)
            {
                bool newPacket = (value & 0x40) != 0;

                int tag;
                if (newPacket)
                {
                    tag = value & 0x3f;
                }
                else
                {
                    tag = (value & 0x3f) >> 2;
                }

                switch ((PacketTag)tag)
                {
                case PacketTag.PublicKey:
                    type = "PUBLIC KEY BLOCK";
                    break;
                case PacketTag.SecretKey:
                    type = "PRIVATE KEY BLOCK";
                    break;
                case PacketTag.Signature:
                    type = "SIGNATURE";
                    break;
                default:
                    type = "MESSAGE";
                    break;
                }

                DoWrite(HeaderStart);
                DoWrite(type);
                DoWrite(HeaderTail);
                DoWrite(NewLine);

                if (m_headers.TryGetValue(HeaderVersion, out var versionHeaders))
                {
                    WriteHeaderEntry(HeaderVersion, versionHeaders[0]);
                }

                foreach (var de in m_headers)
                {
                    string k = de.Key;
                    if (k != HeaderVersion)
                    {
                        foreach (string v in de.Value)
                        {
                            WriteHeaderEntry(k, v);
                        }
                    }
                }

                DoWrite(NewLine);
                start = false;
            }

            if (bufPtr == 3)
            {
                crc?.Update3(buf, 0);
                Encode3(m_outStream, buf);
                bufPtr = 0;
                if ((++chunkCount & 0xf) == 0)
                {
                    DoWrite(NewLine);
                }
            }

            buf[bufPtr++] = value;
        }

        /// <remarks>
        /// Does not dispose/close the underlying stream. So it is possible to write multiple objects using armoring to
        /// a single stream.
        /// </remarks>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (type != null)
                {
                    DoClose();

                    type = null;
                    start = true;
                }
            }
            base.Dispose(disposing);
        }

        private void DoClose()
        {
            if (bufPtr > 0)
            {
                if (crc != null)
                {
                    for (int i = 0; i < bufPtr; ++i)
                    {
                        crc.Update(buf[i]);
                    }
                }
                Encode(m_outStream, buf, bufPtr);
            }

            DoWrite(NewLine);

            if (crc != null)
            {
                m_outStream.WriteByte((byte)'=');

                Pack.UInt24_To_BE((uint)crc.Value, buf);
                Encode3(m_outStream, buf);

                DoWrite(NewLine);
            }

            DoWrite(FooterStart);
            DoWrite(type);
            DoWrite(FooterTail);
            DoWrite(NewLine);

            m_outStream.Flush();

            type = null;
            start = true;
        }

        private void DoWrite(string s)
        {
            byte[] bs = Strings.ToUtf8ByteArray(s);
            m_outStream.Write(bs, 0, bs.Length);
        }

        public static Builder Build() => new Builder();

        public sealed class Builder
        {
            internal readonly Dictionary<string, List<string>> m_headers = new Dictionary<string, List<string>>();
            internal bool m_computeCrcSum = true;

            internal Builder()
            {
            }

            public ArmoredOutputStream Build(Stream output) => new ArmoredOutputStream(output, this);

            /**
             * Set a <pre>Version:</pre> header.
             * Note: Adding version headers to ASCII armored output is discouraged to minimize metadata.
             *
             * @param version version
             * @return builder
             */
            public Builder SetVersion(string version) => SetSingletonHeader(HeaderVersion, version);

            /**
             * Replace the <pre>Comment:</pre> header field with the given comment.
             * If the comment contains newlines, multiple headers will be added, one for each newline.
             * If the comment is <pre>null</pre>, then the output will contain no comments.
             *
             * @param comment comment
             * @return builder
             */
            public Builder SetComment(string comment) => ReplaceHeader(HeaderComment, comment);

            /**
             * Replace the <pre>MessageID:</pre> header field with the given messageId.
             *
             * @param messageId message ID
             * @return builder
             */
            public Builder SetMessageID(string messageID) => ReplaceHeader(HeaderMessageID, messageID);

            /**
             * Replace the <pre>Charset:</pre> header with the given value.
             *
             * @param charset charset
             * @return builder
             */
            public Builder SetCharset(string charset) => ReplaceHeader(HeaderCharset, charset);

            /**
             * Add the given value as one or more additional <pre>Comment:</pre> headers to the already present comments.
             * If the comment contains newlines, multiple headers will be added, one for each newline.
             * If the comment is <pre>null</pre>, this method does nothing.
             *
             * @param comment comment
             * @return builder
             */
            public Builder AddComment(string comment) => AddHeader(HeaderComment, comment);

            public Builder AddEllipsizedComment(string comment)
            {
                int availableCommentCharsPerLine = 64 - (HeaderComment.Length + 2); // ASCII armor width - header len
                comment = comment.Trim();
                if (comment.Length > availableCommentCharsPerLine)
                {
                    comment = comment.Substring(0, availableCommentCharsPerLine - 1) + '…';
                }
                return AddComment(comment);
            }

            public Builder AddSplitMultilineComment(string comment)
            {
                int availableCommentCharsPerLine = 64 - (HeaderComment.Length + 2); // ASCII armor width - header len
                comment = comment.Trim();
                foreach (string commentLine in comment.Split('\n'))
                {
                    string line = commentLine;
                    while (line.Length > availableCommentCharsPerLine)
                    {
                        // split comment into multiple lines
                        AddComment(comment.Substring(0, availableCommentCharsPerLine));
                        line = line.Substring(availableCommentCharsPerLine).Trim();
                    }

                    if (line.Length != 0)
                    {
                        AddComment(line);
                    }
                }
                return this;
            }

            /**
             * Set and replace the given header value with a single-line header.
             * If the value is <pre>null</pre>, this method will remove the header entirely.
             *
             * @param key   header key
             * @param value header value
             * @return builder
             */
            private Builder SetSingletonHeader(string key, string value)
            {
                if (value == null || value.Trim().Length == 0)
                {
                    m_headers.Remove(key);
                }
                else
                {
                    string trimmed = value.Trim();
                    if (trimmed.IndexOf('\n') >= 0 || trimmed.IndexOf('\r') >= 0)
                        throw new ArgumentException($"Armor header value for key {key} cannot contain newlines.");

                    m_headers[key] = new List<string>(){ value };
                }
                return this;
            }

            /**
             * Add a header, splitting it into multiple headers if required (newlines).
             *
             * @param key   key
             * @param value value
             * @return builder
             */
            private Builder AddHeader(String key, String value)
            {
                if (value == null || value.Trim().Length == 0)
                    return this;

                if (!m_headers.TryGetValue(key, out List<string> values))
                {
                    values = new List<String>(1);
                    m_headers[key] = values;
                }

                // handle multi-line values; split on CR, LF and CRLF so an embedded bare CR cannot
                // survive into a single header line and forge structure for a lenient armor reader
                string trimmed = value.Trim();
#if NET5_0_OR_GREATER
                foreach (string lineTrim in trimmed.Split(new char[]{ '\r', '\n' },
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    values.Add(lineTrim);
                }
#else
                foreach (string line in trimmed.Split(new char[]{ '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string lineTrim = line.Trim();
                    if (lineTrim.Length > 0)
                    {
                        values.Add(lineTrim);
                    }
                }
#endif
                return this;
            }

            /**
             * Replace all header values for the given key with the given value.
             * If the value is <pre>null</pre>, existing headers for the given key are removed.
             * The value is split into multiple headers if it contains newlines.
             *
             * @param key   key
             * @param value value
             * @return builder
             */
            private Builder ReplaceHeader(string key, string value)
            {
                if (value == null || value.Trim().Length == 0)
                    return this;

                List<string> values = new List<string>();

                // handle multi-line values; split on CR, LF and CRLF so an embedded bare CR cannot
                // survive into a single header line and forge structure for a lenient armor reader
                string trimmed = value.Trim();
#if NET5_0_OR_GREATER
                foreach (string lineTrim in trimmed.Split(new char[]{ '\r', '\n' },
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    values.Add(lineTrim);
                }
#else
                foreach (string line in trimmed.Split(new char[]{ '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string lineTrim = line.Trim();
                    if (lineTrim.Length > 0)
                    {
                        values.Add(lineTrim);
                    }
                }
#endif

                m_headers[key] = values;
                return this;
            }

            public Builder ClearHeaders()
            {
                m_headers.Clear();
                return this;
            }

            /**
             * Enable calculation and inclusion of the CRC check sum (default is true).
             * @param doComputeCRC true if CRC to be included, false otherwise.
             * @return the current builder instance.
             */
            public Builder EnableCrc(bool doComputeCrc)
            {
                m_computeCrcSum = doComputeCrc;
                return this;
            }
        }
    }
}
