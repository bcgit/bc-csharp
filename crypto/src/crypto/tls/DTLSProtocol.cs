using Org.BouncyCastle.Security;
using System;
using System.IO;
using Org.BouncyCastle.Utilities;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{

    public abstract class DTLSProtocol
    {
        protected readonly SecureRandom secureRandom;

        protected DTLSProtocol(SecureRandom secureRandom)
        {
            if (secureRandom == null)
            {
                throw new ArgumentException("'secureRandom' cannot be null");
            }

            this.secureRandom = secureRandom;
        }

        protected void ProcessFinished(byte[] body, byte[] expected_verify_data)
        {
            MemoryStream buf = new MemoryStream(body);

            byte[] verify_data = TlsUtilities.ReadFully(expected_verify_data.Length, buf);

            TlsProtocol.AssertEmpty(buf);

            if (!Arrays.ConstantTimeAreEqual(expected_verify_data, verify_data))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }

        protected static short EvaluateMaxFragmentLengthExtension(IDictionary clientExtensions, IDictionary serverExtensions, AlertDescription alertDescription)
        {
            short maxFragmentLength = TlsExtensionsUtils.GetMaxFragmentLengthExtension(serverExtensions);
            if (maxFragmentLength >= 0 && maxFragmentLength != TlsExtensionsUtils.GetMaxFragmentLengthExtension(clientExtensions))
            {
                throw new TlsFatalAlert(alertDescription);
            }
            return maxFragmentLength;
        }

        protected static byte[] GenerateCertificate(Certificate certificate)
        {
            MemoryStream buf = new MemoryStream();
            certificate.Encode(buf);
            return buf.ToArray();
        }

        protected static byte[] GenerateSupplementalData(IList supplementalData)
        {
            MemoryStream buf = new MemoryStream();
            TlsProtocol.WriteSupplementalData(buf, supplementalData);
            return buf.ToArray();
        }

        protected static void ValidateSelectedCipherSuite(CipherSuite selectedCipherSuite, AlertDescription alertDescription)
        {
            switch (selectedCipherSuite)
            {
                case CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
                case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
                case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
                case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
                    // TODO Alert
                    throw new InvalidOperationException("RC4 MUST NOT be used with DTLS");
            }
        }
    }

}