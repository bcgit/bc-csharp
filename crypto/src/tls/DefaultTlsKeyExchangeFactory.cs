using System;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>The default factory for TLS key exchange objects.</summary>
    public class DefaultTlsKeyExchangeFactory
        : AbstractTlsKeyExchangeFactory
    {
        /// <inheritdoc/>
        public override TlsKeyExchange CreateDHKeyExchange(int keyExchange)
        {
            return new TlsDHKeyExchange(keyExchange);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateDHanonKeyExchangeClient(int keyExchange,
            TlsDHGroupVerifier dhGroupVerifier)
        {
            return new TlsDHanonKeyExchange(keyExchange, dhGroupVerifier);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateDHanonKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig)
        {
            return new TlsDHanonKeyExchange(keyExchange, dhConfig);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateDheKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        {
            return new TlsDheKeyExchange(keyExchange, dhGroupVerifier);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateDheKeyExchangeServer(int keyExchange, TlsDHConfig dhConfig)
        {
            return new TlsDheKeyExchange(keyExchange, dhConfig);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateECDHKeyExchange(int keyExchange)
        {
            return new TlsECDHKeyExchange(keyExchange);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateECDHanonKeyExchangeClient(int keyExchange)
        {
            return new TlsECDHanonKeyExchange(keyExchange);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateECDHanonKeyExchangeServer(int keyExchange, TlsECConfig ecConfig)
        {
            return new TlsECDHanonKeyExchange(keyExchange, ecConfig);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateECDheKeyExchangeClient(int keyExchange)
        {
            return new TlsECDheKeyExchange(keyExchange);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateECDheKeyExchangeServer(int keyExchange, TlsECConfig ecConfig)
        {
            return new TlsECDheKeyExchange(keyExchange, ecConfig);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreatePskKeyExchangeClient(int keyExchange, TlsPskIdentity pskIdentity,
            TlsDHGroupVerifier dhGroupVerifier)
        {
            return new TlsPskKeyExchange(keyExchange, pskIdentity, dhGroupVerifier);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreatePskKeyExchangeServer(int keyExchange,
            TlsPskIdentityManager pskIdentityManager, TlsDHConfig dhConfig, TlsECConfig ecConfig)
        {
            return new TlsPskKeyExchange(keyExchange, pskIdentityManager, dhConfig, ecConfig);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateRsaKeyExchange(int keyExchange)
        {
            return new TlsRsaKeyExchange(keyExchange);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateSrpKeyExchangeClient(int keyExchange, TlsSrpIdentity srpIdentity,
            TlsSrpConfigVerifier srpConfigVerifier)
        {
            return new TlsSrpKeyExchange(keyExchange, srpIdentity, srpConfigVerifier);
        }

        /// <inheritdoc/>
        public override TlsKeyExchange CreateSrpKeyExchangeServer(int keyExchange, TlsSrpLoginParameters loginParameters)
        {
            return new TlsSrpKeyExchange(keyExchange, loginParameters);
        }
    }
}
