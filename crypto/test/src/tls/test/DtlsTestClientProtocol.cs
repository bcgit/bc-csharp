using System;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class DtlsTestClientProtocol
        : DtlsClientProtocol
    {
        protected readonly TlsTestConfig m_config;

        public DtlsTestClientProtocol(TlsTestConfig config)
            : base()
        {
            this.m_config = config;
        }

        protected override byte[] GenerateCertificateVerify(ClientHandshakeState state,
            DigitallySigned certificateVerify)
        {
            if (certificateVerify.Algorithm != null && m_config.clientAuthSigAlgClaimed != null)
            {
                certificateVerify = new DigitallySigned(m_config.clientAuthSigAlgClaimed, certificateVerify.Signature);
            }

            return base.GenerateCertificateVerify(state, certificateVerify);
        }
    }
}
