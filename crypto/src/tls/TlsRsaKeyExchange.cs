using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS RSA key exchange.</summary>
    // TODO[api] Make sealed
    public class TlsRsaKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.RSA:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", nameof(keyExchange));
            }
        }

        /// <summary>The server credentials.</summary>
        protected TlsCredentialedDecryptor m_serverCredentials = null;
        /// <summary>The server encryptor.</summary>
        protected TlsEncryptor m_serverEncryptor;
        /// <summary>The pre master secret.</summary>
        protected TlsSecret m_preMasterSecret;

        /// <summary>Create a new <see cref="TlsRsaKeyExchange"/>.</summary>
        /// <param name="keyExchange">The key exchange.</param>
        public TlsRsaKeyExchange(int keyExchange)
            : base(CheckKeyExchange(keyExchange))
        {
        }

        /// <inheritdoc/>
        public override void SkipServerCredentials() => new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            m_serverCredentials = TlsUtilities.RequireDecryptorCredentials(serverCredentials);
        }

        /// <inheritdoc/>
        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            m_serverEncryptor = serverCertificate.GetCertificateAt(0).CreateEncryptor(TlsCertificateRole.RsaEncryption);
        }

        /// <inheritdoc/>
        public override short[] GetClientCertificateTypes()
        {
            return new short[]{ ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign,
                ClientCertificateType.ecdsa_sign };
        }

        /// <inheritdoc/>
        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            TlsUtilities.RequireSignerCredentials(clientCredentials);

        /// <inheritdoc/>
        public override void GenerateClientKeyExchange(Stream output)
        {
            m_preMasterSecret = TlsUtilities.GenerateEncryptedPreMasterSecret(m_context, m_serverEncryptor, output);
        }

        /// <inheritdoc/>
        public override void ProcessClientKeyExchange(Stream input)
        {
            byte[] encryptedPreMasterSecret = TlsUtilities.ReadEncryptedPms(m_context, input);

            m_preMasterSecret = m_serverCredentials.Decrypt(new TlsCryptoParameters(m_context),
                encryptedPreMasterSecret);
        }

        /// <inheritdoc/>
        public override TlsSecret GeneratePreMasterSecret()
        {
            TlsSecret tmp = m_preMasterSecret;
            m_preMasterSecret = null;
            return tmp;
        }
    }
}
