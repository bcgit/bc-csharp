using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 7301 Represents a protocol name for use with ALPN.</summary>
    public sealed class ProtocolName
    {
        /// <summary>Create a protocol name from raw bytes.</summary>
        /// <param name="bytes">The bytes of the name.</param>
        /// <returns>The protocol name.</returns>
        public static ProtocolName AsRawBytes(byte[] bytes) => new ProtocolName(Arrays.Clone(bytes));

        /// <summary>Create a protocol name from a string, using its UTF-8 encoding.</summary>
        /// <param name="name">The name.</param>
        /// <returns>The protocol name.</returns>
        public static ProtocolName AsUtf8Encoding(string name) => new ProtocolName(Strings.ToUtf8ByteArray(name));

        /// <summary>The protocol name <c>http/1.1</c>.</summary>
        public static readonly ProtocolName Http_1_1 = AsUtf8Encoding("http/1.1");
        /// <summary>The protocol name <c>spdy/1</c>.</summary>
        public static readonly ProtocolName Spdy_1 = AsUtf8Encoding("spdy/1");
        /// <summary>The protocol name <c>spdy/2</c>.</summary>
        public static readonly ProtocolName Spdy_2 = AsUtf8Encoding("spdy/2");
        /// <summary>The protocol name <c>spdy/3</c>.</summary>
        public static readonly ProtocolName Spdy_3 = AsUtf8Encoding("spdy/3");
        /// <summary>The protocol name <c>stun.turn</c>.</summary>
        public static readonly ProtocolName Stun_Turn = AsUtf8Encoding("stun.turn");
        /// <summary>The protocol name <c>stun.nat-discovery</c>.</summary>
        public static readonly ProtocolName Stun_Nat_Discovery = AsUtf8Encoding("stun.nat-discovery");
        /// <summary>The protocol name <c>h2</c>.</summary>
        public static readonly ProtocolName Http_2_Tls = AsUtf8Encoding("h2");
        /// <summary>The protocol name <c>h2c</c>.</summary>
        public static readonly ProtocolName Http_2_Tcp = AsUtf8Encoding("h2c");
        /// <summary>The protocol name <c>webrtc</c>.</summary>
        public static readonly ProtocolName WebRtc = AsUtf8Encoding("webrtc");
        /// <summary>The protocol name <c>c-webrtc</c>.</summary>
        public static readonly ProtocolName WebRtc_Confidential = AsUtf8Encoding("c-webrtc");
        /// <summary>The protocol name <c>ftp</c>.</summary>
        public static readonly ProtocolName Ftp = AsUtf8Encoding("ftp");
        /// <summary>The protocol name <c>imap</c>.</summary>
        public static readonly ProtocolName Imap = AsUtf8Encoding("imap");
        /// <summary>The protocol name <c>pop3</c>.</summary>
        public static readonly ProtocolName Pop3 = AsUtf8Encoding("pop3");
        /// <summary>The protocol name <c>managesieve</c>.</summary>
        public static readonly ProtocolName ManageSieve = AsUtf8Encoding("managesieve");
        /// <summary>The protocol name <c>coap</c>.</summary>
        public static readonly ProtocolName Coap = AsUtf8Encoding("coap");
        /// <summary>The protocol name <c>xmpp-client</c>.</summary>
        public static readonly ProtocolName Xmpp_Client = AsUtf8Encoding("xmpp-client");
        /// <summary>The protocol name <c>xmpp-server</c>.</summary>
        public static readonly ProtocolName Xmpp_Server = AsUtf8Encoding("xmpp-server");
        /// <summary>The protocol name <c>acme-tls/1</c>.</summary>
        public static readonly ProtocolName Acme_Tls_1 = AsUtf8Encoding("acme-tls/1");
        /// <summary>The protocol name <c>mqtt</c>.</summary>
        public static readonly ProtocolName Oasis_Mqtt = AsUtf8Encoding("mqtt");
        /// <summary>The protocol name <c>dot</c>.</summary>
        public static readonly ProtocolName Dns_Over_Tls = AsUtf8Encoding("dot");
        /// <summary>The protocol name <c>ntske/1</c>.</summary>
        public static readonly ProtocolName Ntske_1 = AsUtf8Encoding("ntske/1");
        /// <summary>The protocol name <c>sunrpc</c>.</summary>
        public static readonly ProtocolName Sun_Rpc = AsUtf8Encoding("sunrpc");
        /// <summary>The protocol name <c>h3</c>.</summary>
        public static readonly ProtocolName Http_3 = AsUtf8Encoding("h3");
        /// <summary>The protocol name <c>smb</c>.</summary>
        public static readonly ProtocolName Smb_2 = AsUtf8Encoding("smb");
        /// <summary>The protocol name <c>irc</c>.</summary>
        public static readonly ProtocolName Irc = AsUtf8Encoding("irc");
        /// <summary>The protocol name <c>nntp</c>.</summary>
        public static readonly ProtocolName Nntp_Reading = AsUtf8Encoding("nntp");
        /// <summary>The protocol name <c>nnsp</c>.</summary>
        public static readonly ProtocolName Nntp_Transit = AsUtf8Encoding("nnsp");
        /// <summary>The protocol name <c>doq</c>.</summary>
        public static readonly ProtocolName Dns_Over_Quic = AsUtf8Encoding("doq");

        private readonly byte[] m_bytes;

        private ProtocolName(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 1 || bytes.Length > 255)
                throw new ArgumentException("must have length from 1 to 255", nameof(bytes));

            m_bytes = bytes;
        }

        /// <summary>Return the bytes.</summary>
        public byte[] GetBytes() => Arrays.Clone(m_bytes);

        /// <summary>Return the utf 8 decoding.</summary>
        public string GetUtf8Decoding() => Strings.FromUtf8ByteArray(m_bytes);

        /// <summary>Encode this <see cref="ProtocolName"/> to a <see cref="Stream"/>.</summary>
        /// <param name="output">the <see cref="Stream"/> to encode to.</param>
        /// <exception cref="IOException"/>
        public void Encode(Stream output) => TlsUtilities.WriteOpaque8(m_bytes, output);

        /// <summary>Parse a <see cref="ProtocolName"/> from a <see cref="Stream"/>.</summary>
        /// <param name="input">the <see cref="Stream"/> to parse from.</param>
        /// <returns>a <see cref="ProtocolName"/> object.</returns>
        /// <exception cref="IOException"/>
        public static ProtocolName Parse(Stream input) => new ProtocolName(TlsUtilities.ReadOpaque8(input, 1));

        /// <inheritdoc/>
        public override bool Equals(object obj) =>
            obj is ProtocolName that && Arrays.AreEqual(m_bytes, that.m_bytes);

        /// <inheritdoc/>
        public override int GetHashCode() => Arrays.GetHashCode(m_bytes);
    }
}
