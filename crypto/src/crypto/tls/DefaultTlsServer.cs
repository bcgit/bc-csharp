using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Agreement;
namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class DefaultTlsServer : AbstractTlsServer
    {
        public DefaultTlsServer()
        {
        }

        public DefaultTlsServer(TlsCipherFactory cipherFactory)
            : base(cipherFactory)
        {

        }

        protected virtual TlsEncryptionCredentials GetRSAEncryptionCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        protected virtual TlsSignerCredentials GetRSASignerCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        protected DHParameters GetDHParameters()
        {
            return DHStandardGroups.rfc5114_1024_160;
        }

        protected override CipherSuite[] CipherSuites
        {
            get
            {
                return new CipherSuite[]{CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                                         CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 
                                         CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                         CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 
                                         CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                         CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 
                                         CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                                         CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, 
                                         CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,};
            }
        }

        public override TlsCredentials Credentials
        {
            get
            {
                switch (selectedCipherSuite)
                {
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
                        return GetRSAEncryptionCredentials();

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
                    case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
                    case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
                        return GetRSASignerCredentials();

                    default:
                        /*
                         * Note: internal error here; selected a key exchange we don't implement!
                         */
                        throw new TlsFatalAlert(AlertDescription.internal_error);
                }
            }
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
                    return CreateDHEKeyExchange(KeyExchangeAlgorithm.DHE_DSS);

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
                case CipherSuite.TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1:
                case CipherSuite.TLS_DHE_RSA_WITH_ESTREAM_SALSA20_UMAC96:
                case CipherSuite.TLS_DHE_RSA_WITH_SALSA20_SHA1:
                case CipherSuite.TLS_DHE_RSA_WITH_SALSA20_UMAC96:
                case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
                    return CreateDHEKeyExchange(KeyExchangeAlgorithm.DHE_RSA);

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
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_UMAC96:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_SALSA20_UMAC96:
                    return CreateECDHEKeyExchange(KeyExchangeAlgorithm.ECDHE_ECDSA);

                case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_UMAC96:
                case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_UMAC96:
                    return CreateECDHEKeyExchange(KeyExchangeAlgorithm.ECDHE_RSA);

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
                case CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_SHA1:
                case CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_UMAC96:
                case CipherSuite.TLS_RSA_WITH_NULL_MD5:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_RSA_WITH_SALSA20_SHA1:
                case CipherSuite.TLS_RSA_WITH_SALSA20_UMAC96:
                case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
                    return CreateRSAKeyExchange();

                default:
                    /*
                     * Note: internal error here; selected a key exchange we don't implement!
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
                case CipherSuite.TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1:
                case CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_SHA1:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.ESTREAM_SALSA20, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DHE_RSA_WITH_ESTREAM_SALSA20_UMAC96:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_UMAC96:
                case CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_UMAC96:
                case CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_UMAC96:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.ESTREAM_SALSA20, MACAlgorithm.umac96);

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

                case CipherSuite.TLS_DHE_RSA_WITH_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1:
                case CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_SHA1:
                case CipherSuite.TLS_RSA_WITH_SALSA20_SHA1:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.SALSA20, MACAlgorithm.hmac_sha1);

                case CipherSuite.TLS_DHE_RSA_WITH_SALSA20_UMAC96:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_SALSA20_UMAC96:
                case CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_UMAC96:
                case CipherSuite.TLS_RSA_WITH_SALSA20_UMAC96:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.SALSA20, MACAlgorithm.umac96);
                case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
                case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
                    return cipherFactory.CreateCipher(context, EncryptionAlgorithm.SEED_CBC, MACAlgorithm.hmac_sha1);

                default:
                    /*
                     * Note: internal error here; selected a cipher suite we don't implement!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        protected TlsKeyExchange CreateDHKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsDHKeyExchange(keyExchange, supportedSignatureAlgorithms, GetDHParameters());
        }

        protected TlsKeyExchange CreateDHEKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsDheKeyExchange(keyExchange, supportedSignatureAlgorithms, GetDHParameters());
        }

        protected TlsKeyExchange CreateECDHKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsECDHKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
                serverECPointFormats);
        }

        protected TlsKeyExchange CreateECDHEKeyExchange(KeyExchangeAlgorithm keyExchange)
        {
            return new TlsECDheKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,
                serverECPointFormats);
        }

        protected TlsKeyExchange CreateRSAKeyExchange()
        {
            return new TlsRsaKeyExchange(supportedSignatureAlgorithms);
        }
    }
}