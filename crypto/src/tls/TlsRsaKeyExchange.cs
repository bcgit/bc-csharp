﻿using System;
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
                throw new ArgumentException("unsupported key exchange algorithm", "keyExchange");
            }
        }

        protected TlsCredentialedDecryptor m_serverCredentials = null;
        protected TlsEncryptor m_serverEncryptor;
        protected TlsSecret m_preMasterSecret;

        public TlsRsaKeyExchange(int keyExchange)
            : base(CheckKeyExchange(keyExchange))
        {
        }

        public override void SkipServerCredentials() => new TlsFatalAlert(AlertDescription.internal_error);

        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            m_serverCredentials = TlsUtilities.RequireDecryptorCredentials(serverCredentials);
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            m_serverEncryptor = serverCertificate.GetCertificateAt(0).CreateEncryptor(TlsCertificateRole.RsaEncryption);
        }

        public override short[] GetClientCertificateTypes()
        {
            return new short[]{ ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign,
                ClientCertificateType.ecdsa_sign };
        }

        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            TlsUtilities.RequireSignerCredentials(clientCredentials);

        public override void GenerateClientKeyExchange(Stream output)
        {
            m_preMasterSecret = TlsUtilities.GenerateEncryptedPreMasterSecret(m_context, m_serverEncryptor, output);
        }

        public override void ProcessClientKeyExchange(Stream input)
        {
            byte[] encryptedPreMasterSecret = TlsUtilities.ReadEncryptedPms(m_context, input);

            m_preMasterSecret = m_serverCredentials.Decrypt(new TlsCryptoParameters(m_context),
                encryptedPreMasterSecret);
        }

        public override TlsSecret GeneratePreMasterSecret()
        {
            TlsSecret tmp = m_preMasterSecret;
            m_preMasterSecret = null;
            return tmp;
        }
    }
}
