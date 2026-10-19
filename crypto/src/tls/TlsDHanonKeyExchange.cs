using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS DH_anon key exchange.</summary>
    // TODO[api] Make sealed
    public class TlsDHanonKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.DH_anon:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", nameof(keyExchange));
            }
        }

        /// <summary>The dh group verifier.</summary>
        // TODO[api] Make readonly
        protected TlsDHGroupVerifier m_dhGroupVerifier;

        /// <summary>The dh config.</summary>
        protected TlsDHConfig m_dhConfig;
        /// <summary>The agreement.</summary>
        protected TlsAgreement m_agreement;

        /// <summary>Create a new <see cref="TlsDHanonKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        /// <param name="dhGroupVerifier">The dh group verifier.</param>
        public TlsDHanonKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
            : this(keyExchange, dhGroupVerifier, null)
        {
        }

        /// <summary>Create a new <see cref="TlsDHanonKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        /// <param name="dhConfig">The dh config.</param>
        public TlsDHanonKeyExchange(int keyExchange, TlsDHConfig dhConfig)
            : this(keyExchange, null, dhConfig)
        {
        }

        private TlsDHanonKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier, TlsDHConfig dhConfig)
            : base(CheckKeyExchange(keyExchange))
        {
            m_dhGroupVerifier = dhGroupVerifier;
            m_dhConfig = dhConfig;
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

            TlsDHUtilities.WriteDHConfig(m_dhConfig, buf);

            m_agreement = m_context.Crypto.CreateDHDomain(m_dhConfig).CreateDH();

            byte[] y = m_agreement.GenerateEphemeral();

            TlsUtilities.WriteOpaque16(y, buf);

            return buf. ToArray();
        }

        /// <inheritdoc/>
        public override void ProcessServerKeyExchange(Stream input)
        {
            m_dhConfig = TlsDHUtilities.ReceiveDHConfig(m_context, m_dhGroupVerifier, input);

            byte[] y = TlsUtilities.ReadOpaque16(input, 1);

            m_agreement = m_context.Crypto.CreateDHDomain(m_dhConfig).CreateDH();

            m_agreement.ReceivePeerValue(y);
        }

        /// <inheritdoc/>
        public override short[] GetClientCertificateTypes() => null;

        /// <inheritdoc/>
        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public override void GenerateClientKeyExchange(Stream output) =>
            TlsUtilities.WriteOpaque16(m_agreement.GenerateEphemeral(), output);

        /// <inheritdoc/>
        public override void ProcessClientCertificate(Certificate clientCertificate) =>
            throw new TlsFatalAlert(AlertDescription.unexpected_message);

        /// <inheritdoc/>
        public override void ProcessClientKeyExchange(Stream input) =>
            m_agreement.ReceivePeerValue(TlsUtilities.ReadOpaque16(input, 1));

        /// <inheritdoc/>
        public override TlsSecret GeneratePreMasterSecret() => m_agreement.CalculateSecret();
    }
}
