using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS DHE key exchange (RFC 4346 section 6.3.2).</summary>
    // TODO[api] Make sealed
    public class TlsDheKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.DHE_DSS:
            case KeyExchangeAlgorithm.DHE_RSA:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", nameof(keyExchange));
            }
        }

        // TODO[api] Make readonly
        protected TlsDHGroupVerifier m_dhGroupVerifier;

        protected TlsDHConfig m_dhConfig;
        protected TlsCredentialedSigner m_serverCredentials = null;
        protected TlsCertificate m_serverCertificate = null;
        protected TlsAgreement m_agreement;

        /// <summary>Create a new <see cref="TlsDheKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        /// <param name="dhGroupVerifier">The dh group verifier.</param>
        public TlsDheKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
            : this(keyExchange, dhGroupVerifier, null)
        {
        }

        /// <summary>Create a new <see cref="TlsDheKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        /// <param name="dhConfig">The dh config.</param>
        public TlsDheKeyExchange(int keyExchange, TlsDHConfig dhConfig)
            : this(keyExchange, null, dhConfig)
        {
        }

        private TlsDheKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier, TlsDHConfig dhConfig)
            : base(CheckKeyExchange(keyExchange))
        {
            m_dhGroupVerifier = dhGroupVerifier;
            m_dhConfig = dhConfig;
        }

        /// <inheritdoc/>
        public override void SkipServerCredentials() => throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            m_serverCredentials = TlsUtilities.RequireSignerCredentials(serverCredentials);
        }

        /// <inheritdoc/>
        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            m_serverCertificate = serverCertificate.GetCertificateAt(0);
        }

        /// <inheritdoc/>
        public override bool RequiresServerKeyExchange => true;

        /// <inheritdoc/>
        public override byte[] GenerateServerKeyExchange()
        {
            DigestInputBuffer digestBuffer = new DigestInputBuffer();

            TlsDHUtilities.WriteDHConfig(m_dhConfig, digestBuffer);

            m_agreement = m_context.Crypto.CreateDHDomain(m_dhConfig).CreateDH();

            byte[] y = m_agreement.GenerateEphemeral();

            TlsUtilities.WriteOpaque16(y, digestBuffer);

            TlsUtilities.GenerateServerKeyExchangeSignature(m_context, m_serverCredentials, digestBuffer);

            return digestBuffer.ToArray();
        }

        /// <inheritdoc/>
        public override void ProcessServerKeyExchange(Stream input)
        {
            DigestInputBuffer digestBuffer = new DigestInputBuffer();
            Stream teeIn = new TeeInputStream(input, digestBuffer);

            m_dhConfig = TlsDHUtilities.ReceiveDHConfig(m_context, m_dhGroupVerifier, teeIn);

            byte[] y = TlsUtilities.ReadOpaque16(teeIn, 1);

            TlsUtilities.VerifyServerKeyExchangeSignature(m_context, input, m_serverCertificate, digestBuffer);

            m_agreement = m_context.Crypto.CreateDHDomain(m_dhConfig).CreateDH();

            m_agreement.ReceivePeerValue(y);
        }

        /// <inheritdoc/>
        public override short[] GetClientCertificateTypes()
        {
            return new short[]{ ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign,
                ClientCertificateType.rsa_sign };
        }

        /// <inheritdoc/>
        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            TlsUtilities.RequireSignerCredentials(clientCredentials);

        /// <inheritdoc/>
        public override void GenerateClientKeyExchange(Stream output) =>
            TlsUtilities.WriteOpaque16(m_agreement.GenerateEphemeral(), output);

        /// <inheritdoc/>
        public override void ProcessClientKeyExchange(Stream input) =>
            m_agreement.ReceivePeerValue(TlsUtilities.ReadOpaque16(input, 1));

        /// <inheritdoc/>
        public override TlsSecret GeneratePreMasterSecret() => m_agreement.CalculateSecret();
    }
}
