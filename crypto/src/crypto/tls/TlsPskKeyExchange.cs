using System;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{
    internal class TlsPskKeyExchange : AbstractTlsKeyExchange
    {
        protected TlsPskIdentity pskIdentity;
        protected DHParameters dhParameters;
        protected NamedCurve[] namedCurves;
        protected ECPointFormat[] clientECPointFormats, serverECPointFormats;

        protected byte[] psk_identity_hint = null;

        protected DHPrivateKeyParameters dhAgreePrivateKey = null;
        protected DHPublicKeyParameters dhAgreePublicKey = null;

        protected AsymmetricKeyParameter serverPublicKey = null;
        protected RsaKeyParameters rsaServerPublicKey = null;
        protected TlsEncryptionCredentials serverCredentials = null;
        protected byte[] premasterSecret;

        public TlsPskKeyExchange(KeyExchangeAlgorithm keyExchange, IList supportedSignatureAlgorithms, TlsPskIdentity pskIdentity,
            DHParameters dhParameters, NamedCurve[] namedCurves, ECPointFormat[] clientECPointFormats, ECPointFormat[] serverECPointFormats)
            : base(keyExchange, supportedSignatureAlgorithms)
        {

            switch (keyExchange)
            {
                case KeyExchangeAlgorithm.DHE_PSK:
                case KeyExchangeAlgorithm.ECDHE_PSK:
                case KeyExchangeAlgorithm.PSK:
                case KeyExchangeAlgorithm.RSA_PSK:
                    break;
                default:
                    throw new ArgumentException("unsupported key exchange algorithm");
            }

            this.pskIdentity = pskIdentity;
            this.dhParameters = dhParameters;
            this.namedCurves = namedCurves;
            this.clientECPointFormats = clientECPointFormats;
            this.serverECPointFormats = serverECPointFormats;
        }

        public override void SkipServerCredentials()
        {
            if (keyExchange == KeyExchangeAlgorithm.RSA_PSK)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            if (!(serverCredentials is TlsEncryptionCredentials))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            ProcessServerCertificate(serverCredentials.Certificate);

            this.serverCredentials = (TlsEncryptionCredentials)serverCredentials;
        }

        public override byte[] GenerateServerKeyExchange()
        {
            // TODO[RFC 4279] Need a server-side PSK API to determine hint and resolve identities to keys
            this.psk_identity_hint = null;

            if (this.psk_identity_hint == null && !RequiresServerKeyExchange)
            {
                return null;
            }

            var buf = new MemoryStream();

            if (this.psk_identity_hint == null)
            {
                TlsUtilities.WriteOpaque16(TlsUtilities.EMPTY_BYTES, buf);
            }
            else
            {
                TlsUtilities.WriteOpaque16(this.psk_identity_hint, buf);
            }

            if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                this.dhAgreePrivateKey = TlsDHUtilities.GenerateEphemeralServerKeyExchange(context.SecureRandom,
                    this.dhParameters, buf);
            }
            else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                // TODO[RFC 5489]
            }

            return buf.ToArray();
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            if (keyExchange != KeyExchangeAlgorithm.RSA_PSK)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            if (serverCertificate.IsEmpty)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }

            X509CertificateStructure x509Cert = serverCertificate.certs[0];
            SubjectPublicKeyInfo keyInfo = x509Cert.SubjectPublicKeyInfo;

            try
            {
                this.serverPublicKey = PublicKeyFactory.CreateKey(keyInfo);
            }
            //			catch (Exception)
            catch (Exception)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
            }

            // Sanity check the PublicKeyFactory
            if (this.serverPublicKey.IsPrivate)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            this.rsaServerPublicKey = ValidateRsaPublicKey((RsaKeyParameters)this.serverPublicKey);

            TlsUtilities.ValidateKeyUsage(x509Cert, KeyUsage.KeyEncipherment);

            base.ProcessServerCertificate(serverCertificate);

            // TODO
            /*
            * Perform various checks per RFC2246 7.4.2: "Unless otherwise specified, the
            * signing algorithm for the certificate must be the same as the algorithm for the
            * certificate key."
            */
        }

        public override bool RequiresServerKeyExchange
        {
            get
            {
                switch (keyExchange)
                {
                    case KeyExchangeAlgorithm.DHE_PSK:
                    case KeyExchangeAlgorithm.ECDHE_PSK:
                        return true;
                    default:
                        return false;
                }
            }
        }

        public override void ProcessServerKeyExchange(Stream input)
        {
            this.psk_identity_hint = TlsUtilities.ReadOpaque16(input);

            if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                ServerDHParams serverDHParams = ServerDHParams.Parse(input);

                this.dhAgreePublicKey = TlsDHUtilities.ValidateDHPublicKey(serverDHParams.PublicKey);
            }
            else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                // TODO[RFC 5489]
            }
        }

        public override void ValidateCertificateRequest(CertificateRequest certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }


        public override void ProcessClientCredentials(TlsCredentials clientCredentials)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public override void GenerateClientKeyExchange(Stream output)
        {
            if (psk_identity_hint == null || psk_identity_hint.Length == 0)
            {
                pskIdentity.SkipIdentityHint();
            }
            else
            {
                pskIdentity.NotifyIdentityHint(psk_identity_hint);
            }

            byte[] psk_identity = pskIdentity.GetPskIdentity();

            TlsUtilities.WriteOpaque16(psk_identity, output);

            if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                this.dhAgreePrivateKey = TlsDHUtilities.GenerateEphemeralClientKeyExchange(context.SecureRandom,
                    dhAgreePublicKey.Parameters, output);
            }
            else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                // TODO[RFC 5489]
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            else if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
            {
                this.premasterSecret = TlsRSAUtils.GenerateEncryptedPreMasterSecret(context, this.rsaServerPublicKey,
                    output);
            }
        }

        public override byte[] GeneratePremasterSecret()
        {
            byte[] psk = pskIdentity.GetPsk();
            byte[] other_secret = GenerateOtherSecret(psk.Length);

            MemoryStream buf = new MemoryStream(4 + other_secret.Length + psk.Length);
            TlsUtilities.WriteOpaque16(other_secret, buf);
            TlsUtilities.WriteOpaque16(psk, buf);
            return buf.ToArray();
        }

        protected byte[] GenerateOtherSecret(int pskLength)
        {
            if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
            {
                if (dhAgreePrivateKey != null)
                {
                    return TlsDHUtilities.CalculateDHBasicAgreement(dhAgreePublicKey, dhAgreePrivateKey);
                }

                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
            {
                // TODO[RFC 5489]
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
            {
                return this.premasterSecret;
            }

            return new byte[pskLength];
        }

        protected RsaKeyParameters ValidateRsaPublicKey(RsaKeyParameters key)
        {
            // TODO What is the minimum bit length required?
            //			key.Modulus.BitLength;

            if (!key.Exponent.IsProbablePrime(2))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            return key;
        }

        //public override void SkipServerKeyExchange()
        //{
        //    if (keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        //    {
        //        throw new TlsFatalAlert(AlertDescription.unexpected_message);
        //    }

        //    this.psk_identity_hint = new byte[0];
        //}

        //public override void SkipClientCredentials()
        //{
        //    // OK
        //}
    }
}
