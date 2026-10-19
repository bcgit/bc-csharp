using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A TLS client that uses a pre-shared key.</summary>
    public class PskTlsClient
        : AbstractTlsClient
    {
        private static readonly int[] DefaultCipherSuites = new int[]
        {
            CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA
        };

        protected readonly TlsPskIdentity m_pskIdentity;

        /// <summary>Create a new <see cref="PskTlsClient"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="identity">The identity.</param>
        /// <param name="psk">The psk.</param>
        public PskTlsClient(TlsCrypto crypto, byte[] identity, byte[] psk)
            : this(crypto, new BasicTlsPskIdentity(identity, psk))
        {
        }

        /// <summary>Create a new <see cref="PskTlsClient"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="pskIdentity">The psk identity.</param>
        public PskTlsClient(TlsCrypto crypto, TlsPskIdentity pskIdentity)
            : base(crypto)
        {
            this.m_pskIdentity = pskIdentity;
        }

        /// <inheritdoc/>
        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.TLSv12.Only();
        }

        /// <inheritdoc/>
        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, DefaultCipherSuites);
        }

        /// <inheritdoc/>
        public override TlsPskIdentity GetPskIdentity()
        {
            return m_pskIdentity;
        }

        /// <exception cref="IOException"/>
        public override TlsAuthentication GetAuthentication()
        {
            /*
             * Note: This method is not called unless a server certificate is sent, which may be the
             * case e.g. for RSA_PSK key exchange.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
