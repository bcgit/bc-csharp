using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    public abstract class DefaultTlsServer
        : AbstractTlsServer
    {
        private static readonly int[] DefaultCipherSuites = new int[]
        {
            /*
             * TLS 1.3
             */
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,

            /*
             * pre-TLS 1.3
             */
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,

            // TODO[api] Remove RSA key exchange cipher suites from default list
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        };

        /// <summary>Create a new <see cref="DefaultTlsServer"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        public DefaultTlsServer(TlsCrypto crypto)
            : base(crypto)
        {
        }

        /// <exception cref="IOException"/>
        protected virtual TlsCredentialedSigner GetDsaSignerCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <exception cref="IOException"/>
        protected virtual TlsCredentialedSigner GetECDsaSignerCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <exception cref="IOException"/>
        protected virtual TlsCredentialedDecryptor GetRsaEncryptionCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <exception cref="IOException"/>
        protected virtual TlsCredentialedSigner GetRsaSignerCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        /// <inheritdoc/>
        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, DefaultCipherSuites);
        }

        /// <inheritdoc/>
        public override TlsCredentials GetCredentials()
        {
            int keyExchangeAlgorithm = m_context.SecurityParameters.KeyExchangeAlgorithm;

            switch (keyExchangeAlgorithm)
            {
            case KeyExchangeAlgorithm.DHE_DSS:
                return GetDsaSignerCredentials();

            case KeyExchangeAlgorithm.ECDHE_ECDSA:
                return GetECDsaSignerCredentials();

            case KeyExchangeAlgorithm.DHE_RSA:
            case KeyExchangeAlgorithm.ECDHE_RSA:
                return GetRsaSignerCredentials();

            case KeyExchangeAlgorithm.RSA:
                return GetRsaEncryptionCredentials();

            default:
                // Note: internal error here; selected a key exchange we don't implement!
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
    }
}
