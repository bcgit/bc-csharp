using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS ECDH_anon key exchange (see RFC 4492).</summary>
    // TODO[api] Make sealed
    public class TlsECDHanonKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.ECDH_anon:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", nameof(keyExchange));
            }
        }

        /// <summary>The ec config.</summary>
        protected TlsECConfig m_ecConfig;
        /// <summary>The agreement.</summary>
        protected TlsAgreement m_agreement;

        /// <summary>Create a new <see cref="TlsECDHanonKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        public TlsECDHanonKeyExchange(int keyExchange)
            : this(keyExchange, null)
        {
        }

        /// <summary>Create a new <see cref="TlsECDHanonKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        /// <param name="ecConfig">The ec config.</param>
        public TlsECDHanonKeyExchange(int keyExchange, TlsECConfig ecConfig)
            : base(CheckKeyExchange(keyExchange))
        {
            m_ecConfig = ecConfig;
        }

        /// <inheritdoc/>
        public override void SkipServerCredentials() {}

        /// <inheritdoc/>
        public override void ProcessServerCredentials(TlsCredentials serverCredentials) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public override void ProcessServerCertificate(Certificate serverCertificate) =>
            throw new TlsFatalAlert(AlertDescription.unexpected_message);

        /// <inheritdoc/>
        public override bool RequiresServerKeyExchange => true;

        /// <inheritdoc/>
        public override byte[] GenerateServerKeyExchange()
        {
            MemoryStream buf = new MemoryStream();

            TlsEccUtilities.WriteECConfig(m_ecConfig, buf);

            m_agreement = m_context.Crypto.CreateECDomain(m_ecConfig).CreateECDH();

            GenerateEphemeral(buf);

            return buf.ToArray();
        }

        /// <inheritdoc/>
        public override void ProcessServerKeyExchange(Stream input)
        {
            m_ecConfig = TlsEccUtilities.ReceiveECDHConfig(m_context, input);

            byte[] point = TlsUtilities.ReadOpaque8(input, 1);

            m_agreement = m_context.Crypto.CreateECDomain(m_ecConfig).CreateECDH();

            ProcessEphemeral(point);
        }

        /// <inheritdoc/>
        public override short[] GetClientCertificateTypes() => null;

        /// <inheritdoc/>
        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public override void GenerateClientKeyExchange(Stream output) => GenerateEphemeral(output);

        /// <inheritdoc/>
        public override void ProcessClientCertificate(Certificate clientCertificate) =>
            throw new TlsFatalAlert(AlertDescription.unexpected_message);

        /// <inheritdoc/>
        public override void ProcessClientKeyExchange(Stream input) =>
            ProcessEphemeral(TlsUtilities.ReadOpaque8(input, 1));

        /// <inheritdoc/>
        public override TlsSecret GeneratePreMasterSecret() => m_agreement.CalculateSecret();

        protected virtual void GenerateEphemeral(Stream output) =>
            TlsUtilities.WriteOpaque8(m_agreement.GenerateEphemeral(), output);

        protected virtual void ProcessEphemeral(byte[] point)
        {
            TlsEccUtilities.CheckPointEncoding(m_ecConfig.NamedGroup, point);

            m_agreement.ReceivePeerValue(point);
        }
    }
}
