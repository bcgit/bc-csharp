using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic output stream.
    */
    public class ArmoredOutputStream
        : BaseOutputStream
    {
        public static readonly string HeaderVersion = "Version";

        private static readonly byte[] encodingTable =
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

        /**
         * encode the input data producing a base 64 encoded byte array.
         */
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
            bs[0] = encodingTable[(d1 >> 2) & 0x3f];

            switch (len)
            {
            case 1:
            {
                bs[1] = encodingTable[(d1 << 4) & 0x3f];
                bs[2] = (byte)'=';
                bs[3] = (byte)'=';
                break;
            }
            case 2:
            {
                int d2 = data[1];
                bs[1] = encodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
                bs[2] = encodingTable[(d2 << 2) & 0x3f];
                bs[3] = (byte)'=';
                break;
            }
            case 3:
            {
                int d2 = data[1];
                int d3 = data[2];
                bs[1] = encodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
                bs[2] = encodingTable[((d2 << 2) | (d3 >> 6)) & 0x3f];
                bs[3] = encodingTable[d3 & 0x3f];
                break;
            }
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            outStream.Write(bs);
#else
            outStream.Write(bs, 0, bs.Length);
#endif
        }

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

            bs[0] = encodingTable[(d1 >> 2) & 0x3f];
            bs[1] = encodingTable[((d1 << 4) | (d2 >> 4)) & 0x3f];
            bs[2] = encodingTable[((d2 << 2) | (d3 >> 6)) & 0x3f];
            bs[3] = encodingTable[d3 & 0x3f];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            outStream.Write(bs);
#else
            outStream.Write(bs, 0, bs.Length);
#endif
        }

        private readonly Stream outStream;
        private byte[]          buf = new byte[3];
        private int             bufPtr = 0;
        private Crc24           crc = new Crc24();
        private int             chunkCount = 0;
        private int             lastb;

        private bool            start = true;
        private bool            clearText = false;
        private bool            newLine = false;

        private string          type;

        private static readonly string    NewLine = Environment.NewLine;
        private static readonly string    headerStart = "-----BEGIN PGP ";
        private static readonly string    headerTail = "-----";
        private static readonly string    footerStart = "-----END PGP ";
        private static readonly string    footerTail = "-----";

        private static string CreateVersion()
        {
            var assembly = Assembly.GetExecutingAssembly();

            var titleAttr = assembly.GetCustomAttribute<AssemblyTitleAttribute>();
            var versionAttr = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>();

            if (titleAttr == null || versionAttr == null)
                return "BouncyCastle (unknown version)";

            return titleAttr.Title + " v" + versionAttr.InformationalVersion;
        }

        private static readonly string Version = CreateVersion();

        private readonly IDictionary<string, IList<string>> m_headers;

        public ArmoredOutputStream(Stream outStream)
        {
            this.outStream = outStream;
            this.m_headers = new Dictionary<string, IList<string>>(1);
            SetHeader(HeaderVersion, Version);
        }

        public ArmoredOutputStream(Stream outStream, IDictionary<string, string> headers)
            : this(outStream)
        {
            foreach (var header in headers)
            {
                var headerList = new List<string>(1);
                headerList.Add(header.Value);

                m_headers[header.Key] = headerList;
            }
        }

        /**
         * Set an additional header entry. Any current value(s) under the same name will be
         * replaced by the new one. A null value will clear the entry for name.         *
         * @param name the name of the header entry.
         * @param v the value of the header entry.
         */
        public void SetHeader(string name, string val)
        {
            if (val == null)
            {
                this.m_headers.Remove(name);
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

        /**
         * Set an additional header entry. The current value(s) will continue to exist together
         * with the new one. Adding a null value has no effect.
         *
         * @param name the name of the header entry.
         * @param value the value of the header entry.
         */
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

        /**
         * Reset the headers to only contain a Version string (if one is present).
         */
        public void ResetHeaders()
        {
            var versions = CollectionUtilities.GetValueOrNull(m_headers, HeaderVersion);

            m_headers.Clear();

            if (versions != null)
            {
                m_headers[HeaderVersion] = versions;
            }
        }

        /**
         * Start a clear text signed message.
         * @param hashAlgorithm
         */
        public void BeginClearText(
            HashAlgorithmTag    hashAlgorithm)
        {
            string    hash;

            switch (hashAlgorithm)
            {
            case HashAlgorithmTag.Sha1:
                hash = "SHA1";
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
            case HashAlgorithmTag.MD2:
                hash = "MD2";
                break;
            case HashAlgorithmTag.MD5:
                hash = "MD5";
                break;
            case HashAlgorithmTag.RipeMD160:
                hash = "RIPEMD160";
                break;
            default:
                throw new IOException("unknown hash algorithm tag in beginClearText: " + hashAlgorithm);
            }

            DoWrite("-----BEGIN PGP SIGNED MESSAGE-----" + NewLine);
            DoWrite("Hash: " + hash + NewLine + NewLine);

            clearText = true;
            newLine = true;
            lastb = 0;
        }

        public void EndClearText()
        {
            clearText = false;
        }

        public override void WriteByte(byte value)
        {
            if (clearText)
            {
                outStream.WriteByte(value);

                if (newLine)
                {
                    if (!(value == '\n' && lastb == '\r'))
                    {
                        newLine = false;
                    }
                    if (value == '-')
                    {
                        outStream.WriteByte((byte)' ');
                        outStream.WriteByte((byte)'-');      // dash escape
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

                DoWrite(headerStart + type + headerTail + NewLine);

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
                crc.Update3(buf, 0);
                Encode3(outStream, buf);
                bufPtr = 0;
                if ((++chunkCount & 0xf) == 0)
                {
                    DoWrite(NewLine);
                }
            }

            buf[bufPtr++] = value;
        }

        /**
         * <b>Note</b>: Close() does not close the underlying stream. So it is possible to write
         * multiple objects using armoring to a single stream.
         */
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
                for (int i = 0; i < bufPtr; ++i)
                {
                    crc.Update(buf[i]);
                }
                Encode(outStream, buf, bufPtr);
            }

            DoWrite(NewLine + '=');

            Pack.UInt24_To_BE((uint)crc.Value, buf);
            Encode3(outStream, buf);

            DoWrite(NewLine);
            DoWrite(footerStart);
            DoWrite(type);
            DoWrite(footerTail);
            DoWrite(NewLine);

            outStream.Flush();
        }

        private void WriteHeaderEntry(
            string name,
            string v)
        {
            DoWrite(name + ": " + v + NewLine);
        }

        private void DoWrite(
            string s)
        {
            byte[] bs = Strings.ToAsciiByteArray(s);
            outStream.Write(bs, 0, bs.Length);
        }
    }
}
