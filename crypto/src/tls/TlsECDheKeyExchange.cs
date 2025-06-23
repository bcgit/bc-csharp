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
                throw new ArgumentException("unsupported key exchange algorithm", "keyExchange");
            }
        }

        protected TlsECConfig m_ecConfig;

        protected TlsCredentialedSigner m_serverCredentials = null;
        protected TlsCertificate m_serverCertificate = null;
        protected TlsAgreement m_agreement;

        public TlsECDheKeyExchange(int keyExchange)
            : this(keyExchange, null)
        {
        }

        public TlsECDheKeyExchange(int keyExchange, TlsECConfig ecConfig)
            : base(CheckKeyExchange(keyExchange))
        {
            m_ecConfig = ecConfig;
        }

        public override void SkipServerCredentials() => throw new TlsFatalAlert(AlertDescription.internal_error);

        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            m_serverCredentials = TlsUtilities.RequireSignerCredentials(serverCredentials);
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            m_serverCertificate = serverCertificate.GetCertificateAt(0);
        }

        public override bool RequiresServerKeyExchange => true;

        public override byte[] GenerateServerKeyExchange()
        {
            DigestInputBuffer digestBuffer = new DigestInputBuffer();

            TlsEccUtilities.WriteECConfig(m_ecConfig, digestBuffer);

            m_agreement = m_context.Crypto.CreateECDomain(m_ecConfig).CreateECDH();

            GenerateEphemeral(digestBuffer);

            TlsUtilities.GenerateServerKeyExchangeSignature(m_context, m_serverCredentials, digestBuffer);

            return digestBuffer.ToArray();
        }

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

        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            TlsUtilities.RequireSignerCredentials(clientCredentials);

        public override void GenerateClientKeyExchange(Stream output) => GenerateEphemeral(output);

        public override void ProcessClientKeyExchange(Stream input) =>
            ProcessEphemeral(TlsUtilities.ReadOpaque8(input, 1));

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
