using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class DefaultTlsClient : AbstractTlsClient
    {   
        public DefaultTlsClient()
        {

        }

        public DefaultTlsClient(TlsCipherFactory cipherFactory)
            : base(cipherFactory)
        {

        }

        public override CipherSuite[] GetCipherSuites()
        {
            return new CipherSuite[]{   CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 
                                        CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 
                                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                        CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 
                                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
                                        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,};
        }


        public override TlsKeyExchange GetKeyExchange()
        {
            switch (selectedCipherSuite)
            {
                case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
                    return CreateDHKeyExchange(KeyExchangeAlgorithm.DH_DSS);

                case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
                    return CreateDHKeyExchange(KeyExchangeAlgorithm.DH_RSA);

                case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
                    return CreateDheKeyExchange(KeyExchangeAlgorithm.DHE_DSS);

                case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
                    return CreateDheKeyExchange(KeyExchangeAlgorithm.DHE_RSA);

                case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
                    return CreateECDHKeyExchange(KeyExchangeAlgorithm.ECDH_ECDSA);

                case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
                    return CreateECDHKeyExchange(KeyExchangeAlgorithm.ECDH_RSA);

                case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
                    return CreateECDheKeyExchange(KeyExchangeAlgorithm.ECDHE_ECDSA);

                case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
                    return CreateECDheKeyExchange(KeyExchangeAlgorithm.ECDHE_RSA);

                case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
                case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
                case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
                    return CreateRsaKeyExchange();

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
                case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.cls_3DES_EDE_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CBC, MACAlgorithm.hmac_sha256);

                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
                case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CCM, MACAlgorithm.Null);

                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_CCM_8, MACAlgorithm.Null);

                case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_128_GCM, MACAlgorithm.Null);

                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha256);

                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CBC, MACAlgorithm.hmac_sha384);

                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
                case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CCM, MACAlgorithm.Null);

                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_CCM_8, MACAlgorithm.Null);

                case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.AES_256_GCM, MACAlgorithm.Null);

                case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.CAMELLIA_128_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.CAMELLIA_256_CBC, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_md5);

                case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.NULL, MACAlgorithm.hmac_sha256);

                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.RC4_128, MACAlgorithm.hmac_md5);

                case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.RC4_128, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.SEED_CBC, MACAlgorithm.hmac_sha1);

                default:
                    /*
                     * Note: internal error here; the TlsProtocol implementation verifies that the
                     * server-selected cipher suite was in the list of client-offered cipher suites, so if
                     * we now can't produce an implementation, we shouldn't have offered it!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        protected virtual TlsKeyExchange CreateDHKeyExchange(KeyExchangeAlgorithm keyExchange)
        {

            return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms, null);
        }

        protected virtual TlsKeyExchange CreateDheKeyExchange(KeyExchangeAlgorithm keyExchange)
        {            
            return new TlsDheKeyExchange(keyExchange, supportedSignatureAlgorithms, null);
        }

        protected virtual TlsKeyExchange CreateECDHKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsECDHKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
                serverECPointFormats);
        }

        protected virtual TlsKeyExchange CreateECDheKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsECDheKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
                serverECPointFormats);
        }

        protected virtual TlsKeyExchange CreateRsaKeyExchange()
        {
            return new TlsRsaKeyExchange(supportedSignatureAlgorithms);
        }
    }
}
