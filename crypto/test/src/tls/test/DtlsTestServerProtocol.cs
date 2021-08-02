using System;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class DtlsTestServerProtocol
        : DtlsServerProtocol
    {
        protected readonly TlsTestConfig m_config;

        public DtlsTestServerProtocol(TlsTestConfig config)
            : base()
        {
            this.m_config = config;
        }
    }
}
