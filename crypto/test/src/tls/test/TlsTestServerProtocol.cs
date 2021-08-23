using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class TlsTestServerProtocol
        : TlsServerProtocol
    {
        protected readonly TlsTestConfig m_config;

        internal TlsTestServerProtocol(Stream stream, TlsTestConfig config)
            : this(stream, stream, config)
        {
        }

        internal TlsTestServerProtocol(Stream input, Stream output, TlsTestConfig config)
            : base(input, output)
        {
            this.m_config = config;
        }
    }
}
