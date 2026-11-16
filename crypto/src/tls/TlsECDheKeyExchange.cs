using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS ECDHE key exchange (see RFC 4492).</summary>
    // TODO[api] Make sealed
    public class TlsECDheKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.ECDHE_ECDSA:
            case KeyExchangeAlgorithm.ECDHE_RSA:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", nameof(keyExchange));
            }
        }

        /// <summary>The ec config.</summary>
        protected TlsECConfig m_ecConfig;
        /// <summary>The server credentials.</summary>
        protected TlsCredentialedSigner m_serverCredentials = null;
        /// <summary>The server certificate.</summary>
        protected TlsCertificate m_serverCertificate = null;
        /// <summary>The agreement.</summary>
        protected TlsAgreement m_agreement;

        /// <summary>Create a new <see cref="TlsECDheKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        public TlsECDheKeyExchange(int keyExchange)
            : this(keyExchange, null)
        {
        }

        /// <summary>Create a new <see cref="TlsECDheKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        /// <param name="ecConfig">The ec config.</param>
        public TlsECDheKeyExchange(int keyExchange, TlsECConfig ecConfig)
            : base(CheckKeyExchange(keyExchange))
        {
            m_ecConfig = ecConfig;
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

            TlsEccUtilities.WriteECConfig(m_ecConfig, digestBuffer);

            m_agreement = m_context.Crypto.CreateECDomain(m_ecConfig).CreateECDH();

            GenerateEphemeral(digestBuffer);

            TlsUtilities.GenerateServerKeyExchangeSignature(m_context, m_serverCredentials, digestBuffer);

            return digestBuffer.ToArray();
        }

        /// <inheritdoc/>
        public override void ProcessServerKeyExchange(Stream input)
        {
            DigestInputBuffer digestBuffer = new DigestInputBuffer();
            Stream teeIn = new TeeInputStream(input, digestBuffer);

            m_ecConfig = TlsEccUtilities.ReceiveECDHConfig(m_context, teeIn);

            byte[] point = TlsUtilities.ReadOpaque8(teeIn, 1);

            TlsUtilities.VerifyServerKeyExchangeSignature(m_context, input, m_serverCertificate, digestBuffer);

            m_agreement = m_context.Crypto.CreateECDomain(m_ecConfig).CreateECDH();

            ProcessEphemeral(point);
        }

        /// <inheritdoc/>
        public override short[] GetClientCertificateTypes()
        {
            /*
             * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
             * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
             * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
             * these algorithms.
             */
            return new short[]{ ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign,
                ClientCertificateType.rsa_sign };
        }

        /// <inheritdoc/>
        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            TlsUtilities.RequireSignerCredentials(clientCredentials);

        /// <inheritdoc/>
        public override void GenerateClientKeyExchange(Stream output) => GenerateEphemeral(output);

        /// <inheritdoc/>
        public override void ProcessClientKeyExchange(Stream input) =>
            ProcessEphemeral(TlsUtilities.ReadOpaque8(input, 1));

        /// <inheritdoc/>
        public override TlsSecret GeneratePreMasterSecret() => m_agreement.CalculateSecret();

        /// <summary>Generate the ephemeral ECDH public value and write it to a stream.</summary>
        /// <param name="output">The stream to write to.</param>
        protected virtual void GenerateEphemeral(Stream output) =>
            TlsUtilities.WriteOpaque8(m_agreement.GenerateEphemeral(), output);

        /// <summary>Process the ephemeral ECDH public value received from the peer.</summary>
        /// <param name="point">The encoded point.</param>
        protected virtual void ProcessEphemeral(byte[] point)
        {
            TlsEccUtilities.CheckPointEncoding(m_ecConfig.NamedGroup, point);

            m_agreement.ReceivePeerValue(point);
        }
    }
}
