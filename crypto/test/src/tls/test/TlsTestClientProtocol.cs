using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class TlsTestClientProtocol
        : TlsClientProtocol
    {
        protected readonly TlsTestConfig m_config;

        internal TlsTestClientProtocol(Stream stream, TlsTestConfig config)
            : this(stream, stream, config)
        {
        }

        internal TlsTestClientProtocol(Stream input, Stream output, TlsTestConfig config)
            : base(input, output)
        {
            this.m_config = config;
        }

        protected override void Send13CertificateVerifyMessage(DigitallySigned certificateVerify)
        {
            if (m_config.clientAuthSigAlgClaimed != null)
            {
                certificateVerify = new DigitallySigned(m_config.clientAuthSigAlgClaimed, certificateVerify.Signature);
            }

            base.Send13CertificateVerifyMessage(certificateVerify);
        }

        protected override void SendCertificateVerifyMessage(DigitallySigned certificateVerify)
        {
            if (certificateVerify.Algorithm != null && m_config.clientAuthSigAlgClaimed != null)
            {
                certificateVerify = new DigitallySigned(m_config.clientAuthSigAlgClaimed, certificateVerify.Signature);
            }

            base.SendCertificateVerifyMessage(certificateVerify);
        }
    }
}
