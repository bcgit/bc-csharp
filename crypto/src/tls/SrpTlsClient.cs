using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A TLS client that uses SRP.</summary>
    public class SrpTlsClient
        : AbstractTlsClient
    {
        private static readonly int[] DefaultCipherSuites = new int[]
        {
            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
        };

        protected readonly TlsSrpIdentity m_srpIdentity;

        /// <summary>Create a new <see cref="SrpTlsClient"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="identity">The identity.</param>
        /// <param name="password">The password.</param>
        public SrpTlsClient(TlsCrypto crypto, byte[] identity, byte[] password)
            : this(crypto, new BasicTlsSrpIdentity(identity, password))
        {
        }

        /// <summary>Create a new <see cref="SrpTlsClient"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        /// <param name="srpIdentity">The srp identity.</param>
        public SrpTlsClient(TlsCrypto crypto, TlsSrpIdentity srpIdentity)
            : base(crypto)
        {
            this.m_srpIdentity = srpIdentity;
        }

        /// <inheritdoc/>
        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, DefaultCipherSuites);
        }

        /// <inheritdoc/>
        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.TLSv12.Only();
        }

        /// <summary>Gets the require srp server extension.</summary>
        protected virtual bool RequireSrpServerExtension
        {
            // No explicit guidance in RFC 5054; by default an (empty) extension from server is optional
            get { return false; }
        }

        /// <exception cref="IOException"/>
        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            var clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(
                base.GetClientExtensions());
            TlsSrpUtilities.AddSrpExtension(clientExtensions, m_srpIdentity.GetSrpIdentity());
            return clientExtensions;
        }

        /// <exception cref="IOException"/>
        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            if (!TlsUtilities.HasExpectedEmptyExtensionData(serverExtensions, ExtensionType.srp,
                AlertDescription.illegal_parameter))
            {
                if (RequireSrpServerExtension)
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            base.ProcessServerExtensions(serverExtensions);
        }

        /// <inheritdoc/>
        public override TlsSrpIdentity GetSrpIdentity()
        {
            return m_srpIdentity;
        }

        /// <exception cref="IOException"/>
        public override TlsAuthentication GetAuthentication()
        {
            /*
             * Note: This method is not called unless a server certificate is sent, which may be the
             * case e.g. for SRP_DSS or SRP_RSA key exchange.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
