using System;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class PskTlsClient
        :   AbstractTlsClient
    {
        protected TlsPskIdentity mPskIdentity;

        public PskTlsClient(TlsPskIdentity pskIdentity)
            :   this(new DefaultTlsCipherFactory(), pskIdentity)
        {
        }

        public PskTlsClient(TlsCipherFactory cipherFactory, TlsPskIdentity pskIdentity)
            :   base(cipherFactory)
        {
            this.mPskIdentity = pskIdentity;
        }

        public override int[] GetCipherSuites()
        {
            return new int[] {
                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA,
                CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA,
                CipherSuite.TLS_PSK_WITH_RC4_128_SHA,
            };
        }

        public override TlsKeyExchange GetKeyExchange()
        {
            switch (mSelectedCipherSuite)
            {
            case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
                return CreatePskKeyExchange(KeyExchangeAlgorithm.PSK);

            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
                return CreatePskKeyExchange(KeyExchangeAlgorithm.RSA_PSK);

            case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
                return CreatePskKeyExchange(KeyExchangeAlgorithm.DHE_PSK);

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
            switch (mSelectedCipherSuite)
            {
            case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
                return mCipherFactory.CreateCipher(mContext, EncryptionAlgorithm.cls_3DES_EDE_CBC,
                    MacAlgorithm.hmac_sha1);

            case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
                return mCipherFactory.CreateCipher(mContext, EncryptionAlgorithm.AES_128_CBC,
                    MacAlgorithm.hmac_sha1);

            case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
                return mCipherFactory.CreateCipher(mContext, EncryptionAlgorithm.AES_256_CBC,
                    MacAlgorithm.hmac_sha1);

            case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
            case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
                return mCipherFactory.CreateCipher(mContext, EncryptionAlgorithm.RC4_128,
                    MacAlgorithm.hmac_sha1);

            default:
                /*
                 * Note: internal error here; the TlsProtocol implementation verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher suites, so if
                 * we now can't produce an implementation, we shouldn't have offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        protected virtual TlsKeyExchange CreatePskKeyExchange(int keyExchange)
        {
            return new TlsPskKeyExchange(mContext, keyExchange, mPskIdentity);
        }
    }
}
