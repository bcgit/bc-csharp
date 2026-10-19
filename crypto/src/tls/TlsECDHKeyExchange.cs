using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS ECDH key exchange (see RFC 4492).</summary>
    // TODO[api] Make sealed
    public class TlsECDHKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.ECDH_ECDSA:
            case KeyExchangeAlgorithm.ECDH_RSA:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", nameof(keyExchange));
            }
        }

        /// <summary>The agreement credentials.</summary>
        protected TlsCredentialedAgreement m_agreementCredentials;
        /// <summary>The ecdh peer certificate.</summary>
        protected TlsCertificate m_ecdhPeerCertificate;

        /// <summary>Create a new <see cref="TlsECDHKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        public TlsECDHKeyExchange(int keyExchange)
            : base(CheckKeyExchange(keyExchange))
        {
        }

        /// <inheritdoc/>
        public override void SkipServerCredentials() => throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            m_agreementCredentials = TlsUtilities.RequireAgreementCredentials(serverCredentials);
        }

        /// <inheritdoc/>
        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            m_ecdhPeerCertificate = serverCertificate.GetCertificateAt(0).CheckUsageInRole(TlsCertificateRole.ECDH);
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
            return new short[]{ ClientCertificateType.ecdsa_fixed_ecdh, ClientCertificateType.rsa_fixed_ecdh };
        }

        /// <inheritdoc/>
        public override void SkipClientCredentials() => throw new TlsFatalAlert(AlertDescription.unexpected_message);

        /// <inheritdoc/>
        public override void ProcessClientCredentials(TlsCredentials clientCredentials)
        {
            m_agreementCredentials = TlsUtilities.RequireAgreementCredentials(clientCredentials);
        }

        /// <inheritdoc/>
        public override void GenerateClientKeyExchange(Stream output)
        {
            // In this case, the Client Key Exchange message will be sent, but will be empty.
        }

        /// <inheritdoc/>
        public override void ProcessClientCertificate(Certificate clientCertificate)
        {
            m_ecdhPeerCertificate = clientCertificate.GetCertificateAt(0).CheckUsageInRole(TlsCertificateRole.ECDH);
        }

        /// <inheritdoc/>
        public override void ProcessClientKeyExchange(Stream input)
        {
            // For ecdsa_fixed_ecdh and rsa_fixed_ecdh, the key arrived in the client certificate
        }

        /// <inheritdoc/>
        public override bool RequiresCertificateVerify => false;

        /// <inheritdoc/>
        public override TlsSecret GeneratePreMasterSecret() =>
            m_agreementCredentials.GenerateAgreement(m_ecdhPeerCertificate);
    }
}
