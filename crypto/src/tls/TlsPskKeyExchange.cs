﻿using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS PSK key exchange (RFC 4279).</summary>
    // TODO[api] Make sealed
    public class TlsPskKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.DHE_PSK:
            case KeyExchangeAlgorithm.ECDHE_PSK:
            case KeyExchangeAlgorithm.PSK:
            case KeyExchangeAlgorithm.RSA_PSK:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", "keyExchange");
            }
        }

        protected TlsPskIdentity m_pskIdentity;
        protected TlsPskIdentityManager m_pskIdentityManager;
        protected TlsDHGroupVerifier m_dhGroupVerifier;

        protected byte[] m_psk_identity_hint = null;
        protected byte[] m_psk = null;

        protected TlsDHConfig m_dhConfig;
        protected TlsECConfig m_ecConfig;
        protected TlsAgreement m_agreement;

        protected TlsCredentialedDecryptor m_serverCredentials = null;
        protected TlsEncryptor m_serverEncryptor;
        protected TlsSecret m_preMasterSecret;

        public TlsPskKeyExchange(int keyExchange, TlsPskIdentity pskIdentity, TlsDHGroupVerifier dhGroupVerifier)
            : this(keyExchange, pskIdentity, null, dhGroupVerifier, null, null)
        {
        }

        public TlsPskKeyExchange(int keyExchange, TlsPskIdentityManager pskIdentityManager,
            TlsDHConfig dhConfig, TlsECConfig ecConfig)
            : this(keyExchange, null, pskIdentityManager, null, dhConfig, ecConfig)
        {
        }

        private TlsPskKeyExchange(int keyExchange, TlsPskIdentity pskIdentity, TlsPskIdentityManager pskIdentityManager,
            TlsDHGroupVerifier dhGroupVerifier, TlsDHConfig dhConfig, TlsECConfig ecConfig)
            : base(CheckKeyExchange(keyExchange))
        {
            m_pskIdentity = pskIdentity;
            m_pskIdentityManager = pskIdentityManager;
            m_dhGroupVerifier = dhGroupVerifier;
            m_dhConfig = dhConfig;
            m_ecConfig = ecConfig;
        }

        public override void SkipServerCredentials()
        {
            if (m_keyExchange == KeyExchangeAlgorithm.RSA_PSK)
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            if (m_keyExchange != KeyExchangeAlgorithm.RSA_PSK)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_serverCredentials = TlsUtilities.RequireDecryptorCredentials(serverCredentials);
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            if (m_keyExchange != KeyExchangeAlgorithm.RSA_PSK)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);

            m_serverEncryptor = serverCertificate.GetCertificateAt(0).CreateEncryptor(
                TlsCertificateRole.RsaEncryption);
        }

        public override byte[] GenerateServerKeyExchange()
        {
            m_psk_identity_hint = m_pskIdentityManager.GetHint();

            if (m_psk_identity_hint == null && !RequiresServerKeyExchange)
                return null;

            MemoryStream buf = new MemoryStream();

            if (m_psk_identity_hint == null)
            {
                TlsUtilities.WriteOpaque16(TlsUtilities.EmptyBytes, buf);
            }
            else
            {
                TlsUtilities.WriteOpaque16(m_psk_identity_hint, buf);
            }

            if (m_keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                if (m_dhConfig == null)
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                TlsDHUtilities.WriteDHConfig(m_dhConfig, buf);

                m_agreement = m_context.Crypto.CreateDHDomain(m_dhConfig).CreateDH();

                GenerateEphemeralDH(buf);
            }
            else if (m_keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                if (m_ecConfig == null)
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                TlsEccUtilities.WriteECConfig(m_ecConfig, buf);

                m_agreement = m_context.Crypto.CreateECDomain(m_ecConfig).CreateECDH();

                GenerateEphemeralECDH(buf);
            }

            return buf.ToArray();
        }

        public override bool RequiresServerKeyExchange =>
            m_keyExchange == KeyExchangeAlgorithm.DHE_PSK ||
            m_keyExchange == KeyExchangeAlgorithm.ECDHE_PSK;

        public override void ProcessServerKeyExchange(Stream input)
        {
            m_psk_identity_hint = TlsUtilities.ReadOpaque16(input);

            if (m_keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                m_dhConfig = TlsDHUtilities.ReceiveDHConfig(m_context, m_dhGroupVerifier, input);

                byte[] y = TlsUtilities.ReadOpaque16(input, 1);

                m_agreement = m_context.Crypto.CreateDHDomain(m_dhConfig).CreateDH();

                ProcessEphemeralDH(y);
            }
            else if (m_keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                m_ecConfig = TlsEccUtilities.ReceiveECDHConfig(m_context, input);

                byte[] point = TlsUtilities.ReadOpaque8(input, 1);

                m_agreement = m_context.Crypto.CreateECDomain(m_ecConfig).CreateECDH();

                ProcessEphemeralECDH(point);
            }
        }

        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        public override void GenerateClientKeyExchange(Stream output)
        {
            if (m_psk_identity_hint == null)
            {
                m_pskIdentity.SkipIdentityHint();
            }
            else
            {
                m_pskIdentity.NotifyIdentityHint(m_psk_identity_hint);
            }

            byte[] psk_identity = m_pskIdentity.GetPskIdentity();
            if (psk_identity == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_psk = m_pskIdentity.GetPsk();
            if (m_psk == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            TlsUtilities.WriteOpaque16(psk_identity, output);

            m_context.SecurityParameters.m_pskIdentity = Arrays.Clone(psk_identity);

            if (m_keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                GenerateEphemeralDH(output);
            }
            else if (m_keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                GenerateEphemeralECDH(output);
            }
            else if (m_keyExchange == KeyExchangeAlgorithm.RSA_PSK)
            {
                m_preMasterSecret = TlsUtilities.GenerateEncryptedPreMasterSecret(m_context, m_serverEncryptor, output);
            }
        }

        public override void ProcessClientKeyExchange(Stream input)
        {
            byte[] psk_identity = TlsUtilities.ReadOpaque16(input);

            m_psk = m_pskIdentityManager.GetPsk(psk_identity);
            if (m_psk == null)
                throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);

            m_context.SecurityParameters.m_pskIdentity = psk_identity;

            if (m_keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                byte[] y = TlsUtilities.ReadOpaque16(input, 1);

                ProcessEphemeralDH(y);
            }
            else if (m_keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                byte[] point = TlsUtilities.ReadOpaque8(input, 1);

                ProcessEphemeralECDH(point);
            }
            else if (m_keyExchange == KeyExchangeAlgorithm.RSA_PSK)
            {
                byte[] encryptedPreMasterSecret = TlsUtilities.ReadEncryptedPms(m_context, input);

                m_preMasterSecret = m_serverCredentials.Decrypt(new TlsCryptoParameters(m_context),
                    encryptedPreMasterSecret);
            }
        }

        public override TlsSecret GeneratePreMasterSecret()
        {
            byte[] other_secret = GenerateOtherSecret(m_psk.Length);

            MemoryStream buf = new MemoryStream(4 + other_secret.Length + m_psk.Length);
            TlsUtilities.WriteOpaque16(other_secret, buf);
            TlsUtilities.WriteOpaque16(m_psk, buf);

            Array.Clear(m_psk, 0, m_psk.Length);
            m_psk = null;

            return m_context.Crypto.CreateSecret(buf.ToArray());
        }

        protected virtual void GenerateEphemeralDH(Stream output) =>
            TlsUtilities.WriteOpaque16(m_agreement.GenerateEphemeral(), output);

        protected virtual void GenerateEphemeralECDH(Stream output) =>
            TlsUtilities.WriteOpaque8(m_agreement.GenerateEphemeral(), output);

        protected virtual byte[] GenerateOtherSecret(int pskLength)
        {
            if (m_keyExchange == KeyExchangeAlgorithm.PSK)
                return new byte[pskLength];

            if (m_keyExchange == KeyExchangeAlgorithm.DHE_PSK ||
                m_keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                if (m_agreement != null)
                    return m_agreement.CalculateSecret().Extract();
            }

            if (m_keyExchange == KeyExchangeAlgorithm.RSA_PSK)
            {
                if (m_preMasterSecret != null)
                    return m_preMasterSecret.Extract();
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        protected virtual void ProcessEphemeralDH(byte[] y) => m_agreement.ReceivePeerValue(y);

        protected virtual void ProcessEphemeralECDH(byte[] point)
        {
            TlsEccUtilities.CheckPointEncoding(m_ecConfig.NamedGroup, point);

            m_agreement.ReceivePeerValue(point);
        }
    }
}
