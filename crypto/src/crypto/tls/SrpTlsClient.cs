using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class SrpTlsClient
        : AbstractTlsClient
    {
        public const ExtensionType EXT_SRP = ExtensionType.srp;
        protected byte[] identity;
        protected byte[] password;


        public SrpTlsClient(byte[] identity, byte[] password)
        {
            this.identity = Arrays.Clone(identity);
            this.password = Arrays.Clone(password);
        }

        public SrpTlsClient(TlsCipherFactory cipherFactory, byte[] identity, byte[] password)
            : base(cipherFactory)
        {
            this.identity = Arrays.Clone(identity);
            this.password = Arrays.Clone(password);
        }

        public override CipherSuite[] GetCipherSuites()
        {
            return new CipherSuite[] {
				CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
				CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
			};
        }

        public override IDictionary GetClientExtensions()
        {
            IDictionary clientExtensions = Platform.CreateHashtable();
            if (clientExtensions == null)
            {
                clientExtensions = Platform.CreateHashtable();
            }

            MemoryStream srpData = new MemoryStream();
            TlsUtilities.WriteOpaque8(this.identity, srpData);
            clientExtensions[ExtensionType.srp] = srpData.ToArray();

            return clientExtensions;
        }

        public override void ProcessServerExtensions(IDictionary serverExtensions)
        {
            // No explicit guidance in RFC 5054 here; we allow an optional empty extension from server
            if (serverExtensions != null)
            {
                byte[] extension_data = (byte[])serverExtensions[EXT_SRP];
                if (extension_data != null && extension_data.Length > 0)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        public override TlsKeyExchange GetKeyExchange()
        {
            switch (selectedCipherSuite)
            {
                case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
                    return CreateSrpKeyExchange(KeyExchangeAlgorithm.SRP);

                case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
                    return CreateSrpKeyExchange(KeyExchangeAlgorithm.SRP_RSA);

                case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                    return CreateSrpKeyExchange(KeyExchangeAlgorithm.SRP_DSS);

                default:
                    /*
                     * Note: internal error here; the TlsProtocolHandler verifies that the
                     * server-selected cipher suite was in the list of client-offered cipher
                     * suites, so if we now can't produce an implementation, we shouldn't have
                     * offered it!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public override TlsCipher GetCipher()
        {
            switch (selectedCipherSuite)
            {
                case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.cls_3DES_EDE_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha1);

                default:
                    /*
                     * Note: internal error here; the TlsProtocolHandler verifies that the
                     * server-selected cipher suite was in the list of client-offered cipher
                     * suites, so if we now can't produce an implementation, we shouldn't have
                     * offered it!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        protected virtual TlsKeyExchange CreateSrpKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsSrpKeyExchange(keyExchange, supportedSignatureAlgorithms, identity, password);
        }
    }
}
