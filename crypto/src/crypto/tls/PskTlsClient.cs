using System;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class PskTlsClient : AbstractTlsClient
    {
        protected TlsPskIdentity pskIdentity;

        public PskTlsClient(TlsPskIdentity pskIdentity)
            : base()
        {
            this.pskIdentity = pskIdentity;
        }

        public PskTlsClient(TlsCipherFactory cipherFactory, TlsPskIdentity pskIdentity)
            : base(cipherFactory)
        {
            this.pskIdentity = pskIdentity;
        }        

        public override CipherSuite[] GetCipherSuites()
        {
            return new CipherSuite[]{ CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA,
            CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_PSK_WITH_RC4_128_SHA, };
        }

        public override TlsKeyExchange GetKeyExchange()
        {
            switch (selectedCipherSuite)
            {
                case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
                case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
                    return CreatePSKKeyExchange(KeyExchangeAlgorithm.DHE_PSK);

                case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
                    return CreatePSKKeyExchange(KeyExchangeAlgorithm.ECDHE_PSK);

                case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
                case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
                case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
                    return CreatePSKKeyExchange(KeyExchangeAlgorithm.PSK);

                case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
                    return CreatePSKKeyExchange(KeyExchangeAlgorithm.RSA_PSK);

                default:
                    /*
                     * Note: internal error here; the TlsProtocol implementation verifies that the
                     * server-selected cipher suite was in the list of client-offered cipher suites, so if
                     * we now can't produce an implementation, we shouldn't have offered it!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public override TlsCipher GetCipher()
        {
            switch (selectedCipherSuite)
            {
                case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.cls_3DES_EDE_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha256);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
                case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CCM, MACAlgorithm.Null);

                case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CCM_8, MACAlgorithm.Null);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_GCM, MACAlgorithm.Null);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha384);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
                case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CCM, MACAlgorithm.Null);

                case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CCM_8, MACAlgorithm.Null);

                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_GCM, MACAlgorithm.Null);

                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha256);

                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha384);

                case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
                case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.RC4_128, MACAlgorithm.hmac_sha1);

                default:
                    /*
                     * Note: internal error here; the TlsProtocol implementation verifies that the
                     * server-selected cipher suite was in the list of client-offered cipher suites, so if
                     * we now can't produce an implementation, we shouldn't have offered it!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        protected TlsKeyExchange CreatePSKKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsPskKeyExchange(keyExchange, supportedSignatureAlgorithms, pskIdentity, null, namedCurves,
                clientECPointFormats, serverECPointFormats);
        }
    }
}
