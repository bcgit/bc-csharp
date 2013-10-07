using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{
    /// <summary>
    /// TLS 1.0 RSA key exchange.
    /// </summary>
    internal class TlsRsaKeyExchange
        : AbstractTlsKeyExchange
    {
        protected AsymmetricKeyParameter serverPublicKey = null;
        protected RsaKeyParameters rsaServerPublicKey = null;
        protected TlsEncryptionCredentials serverCredentials = null;
        protected byte[] premasterSecret;

        public TlsRsaKeyExchange(IList supportedSignatureAlgorithms)
            : base(KeyExchangeAlgorithm.RSA, supportedSignatureAlgorithms)
        {

        }

        public override void SkipServerCredentials()
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            if (!(serverCredentials is TlsEncryptionCredentials))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }            

            ProcessServerCertificate(serverCredentials.Certificate);

            this.serverCredentials = serverCredentials as TlsEncryptionCredentials;
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            if (serverCertificate.IsEmpty)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }

            var x509Cert = serverCertificate.GetCertificateAt(0);

            SubjectPublicKeyInfo keyInfo = x509Cert.SubjectPublicKeyInfo;
            try
            {
                this.serverPublicKey = PublicKeyFactory.CreateKey(keyInfo);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
            }

            // Sanity check the PublicKeyFactory
            if (this.serverPublicKey.IsPrivate)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            this.rsaServerPublicKey = ValidateRsaPublicKey((RsaKeyParameters)this.serverPublicKey);

            TlsUtilities.ValidateKeyUsage(x509Cert, KeyUsage.KeyEncipherment);

            base.ProcessServerCertificate(serverCertificate);
        }

        public override void ValidateCertificateRequest(CertificateRequest certificateRequest)
        {
            ClientCertificateType[] types = certificateRequest.CertificateTypes;
            foreach (ClientCertificateType type in types)
            {
                switch (type)
                {
                    case ClientCertificateType.rsa_sign:
                    case ClientCertificateType.dss_sign:
                    case ClientCertificateType.ecdsa_sign:
                        break;
                    default:
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        public override void ProcessClientCredentials(TlsCredentials clientCredentials)
        {
            if (!(clientCredentials is TlsSignerCredentials))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public override void GenerateClientKeyExchange(Stream output)
        {
            this.premasterSecret = TlsRSAUtilities.GenerateEncryptedPreMasterSecret(context, this.rsaServerPublicKey, output);
        }

        public override void ProcessClientKeyExchange(Stream input)
        {
            byte[] encryptedPreMasterSecret;
            if (context.ServerVersion.IsSSL)
            {
                // TODO Do any SSLv3 clients actually include the length?
                encryptedPreMasterSecret = Streams.ReadAll(input);
            }
            else
            {
                encryptedPreMasterSecret = TlsUtilities.ReadOpaque16(input);
            }

            ProtocolVersion clientVersion = context.ClientVersion;

            /*
             * RFC 5246 7.4.7.1.
             */
            {
                // TODO Provide as configuration option?
                bool versionNumberCheckDisabled = false;

                /*
                 * See notes regarding Bleichenbacher/Klima attack. The code here implements the first
                 * construction proposed there, which is RECOMMENDED.
                 */
                byte[] R = new byte[48];
                this.context.SecureRandom.NextBytes(R);

                byte[] M = TlsUtilities.EMPTY_BYTES;
                try
                {
                    M = serverCredentials.DecryptPreMasterSecret(encryptedPreMasterSecret);
                }
                catch 
                {
                    /*
                     * In any case, a TLS server MUST NOT generate an alert if processing an
                     * RSA-encrypted premaster secret message fails, or the version number is not as
                     * expected. Instead, it MUST continue the handshake with a randomly generated
                     * premaster secret.
                     */
                }

                if (M.Length != 48)
                {
                    TlsUtilities.WriteVersion(clientVersion, R, 0);
                    this.premasterSecret = R;
                }
                else
                {
                    /*
                     * If ClientHello.client_version is TLS 1.1 or higher, server implementations MUST
                     * check the version number [..].
                     */
                    if (versionNumberCheckDisabled && clientVersion.IsEqualOrEarlierVersionOf(ProtocolVersion.TLSv10))
                    {
                        /*
                         * If the version number is TLS 1.0 or earlier, server implementations SHOULD
                         * check the version number, but MAY have a configuration option to disable the
                         * check.
                         */
                    }
                    else
                    {
                        /*
                         * Note that explicitly constructing the pre_master_secret with the
                         * ClientHello.client_version produces an invalid master_secret if the client
                         * has sent the wrong version in the original pre_master_secret.
                         */
                        TlsUtilities.WriteVersion(clientVersion, M, 0);
                    }
                    this.premasterSecret = M;
                }
            }
        }

        public override byte[] GeneratePremasterSecret()
        {
            if (this.premasterSecret == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            byte[] tmp = this.premasterSecret;
            this.premasterSecret = null;
            return tmp;
        }

        // Would be needed to process RSA_EXPORT server key exchange
        //	    protected virtual void ProcessRsaServerKeyExchange(Stream input, ISigner signer)
        //	    {
        //	        Stream sigIn = input;
        //	        if (signer != null)
        //	        {
        //	            sigIn = new SignerStream(input, signer, null);
        //	        }
        //
        //	        byte[] modulusBytes = TlsUtilities.ReadOpaque16(sigIn);
        //	        byte[] exponentBytes = TlsUtilities.ReadOpaque16(sigIn);
        //
        //	        if (signer != null)
        //	        {
        //	            byte[] sigByte = TlsUtilities.ReadOpaque16(input);
        //
        //	            if (!signer.VerifySignature(sigByte))
        //	            {
        //	                handler.FailWithError(AlertLevel.fatal, AlertDescription.bad_certificate);
        //	            }
        //	        }
        //
        //	        BigInteger modulus = new BigInteger(1, modulusBytes);
        //	        BigInteger exponent = new BigInteger(1, exponentBytes);
        //
        //	        this.rsaServerPublicKey = ValidateRSAPublicKey(new RsaKeyParameters(false, modulus, exponent));
        //	    }

        protected virtual RsaKeyParameters ValidateRsaPublicKey(RsaKeyParameters key)
        {
            // TODO What is the minimum bit length required?
            //			key.Modulus.BitLength;

            if (!key.Exponent.IsProbablePrime(2))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            return key;
        }
    }
}
