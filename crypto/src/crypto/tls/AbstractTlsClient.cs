
using System.Collections.Generic;
using System.Collections;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class AbstractTlsClient : AbstractTlsPeer, TlsClient
    {
        protected TlsCipherFactory cipherFactory;
        protected TlsClientContext context;

        protected IList supportedSignatureAlgorithms;
        protected NamedCurve[] namedCurves;
        protected ECPointFormat[] clientECPointFormats, serverECPointFormats;

        protected CipherSuite selectedCipherSuite;
        protected CompressionMethod selectedCompressionMethod;

        public AbstractTlsClient()
            : this(new DefaultTlsCipherFactory())
        {

        }

        public AbstractTlsClient(TlsCipherFactory cipherFactory)
        {
            this.cipherFactory = cipherFactory;
        }

        public void Init(TlsClientContext context)
        {
            this.context = context;
        }

        public virtual TlsSession SessionToResume
        {
            get
            {
                return null;
            }
        }

        /**
         * RFC 5246 E.1. "TLS clients that wish to negotiate with older servers MAY send any value
         * {03,XX} as the record layer version number. Typical values would be {03,00}, the lowest
         * version number supported by the client, and the value of ClientHello.client_version. No
         * single value will guarantee interoperability with all old servers, but this is a complex
         * topic beyond the scope of this document."
         */
        public virtual ProtocolVersion ClientHelloRecordLayerVersion
        {
            get
            {
                // "{03,00}"
                // return ProtocolVersion.SSLv3;

                // "the lowest version number supported by the client"
                // return getMinimumServerVersion();

                // "the value of ClientHello.client_version"
                return this.ClientVersion;
            }
        }

        public virtual ProtocolVersion ClientVersion
        {
            get
            {
                return ProtocolVersion.TLSv11;
            }
        }               

        public virtual IDictionary GetClientExtensions()
        {
            IDictionary clientExtensions = null;

            ProtocolVersion clientVersion = context.ClientVersion;

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior to 1.2.
             * Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(clientVersion))
            {
                // TODO Provide a way for the user to specify the acceptable hash/signature algorithms.

                short[] hashAlgorithms = new short[]{ HashAlgorithm.sha512, HashAlgorithm.sha384, HashAlgorithm.sha256,
                HashAlgorithm.sha224, HashAlgorithm.sha1 };

                // TODO Sort out ECDSA signatures and add them as the preferred option here
                short[] signatureAlgorithms = new short[] { SignatureAlgorithm.rsa };

                this.supportedSignatureAlgorithms = Platform.CreateArrayList();
                for (int i = 0; i < hashAlgorithms.Length; ++i)
                {
                    for (int j = 0; j < signatureAlgorithms.Length; ++j)
                    {
                        this.supportedSignatureAlgorithms.Add(new SignatureAndHashAlgorithm(hashAlgorithms[i],
                            signatureAlgorithms[j]));
                    }
                }

                /*
                 * RFC 5264 7.4.3. Currently, DSA [DSS] may only be used with SHA-1.
                 */
                this.supportedSignatureAlgorithms.Add(new SignatureAndHashAlgorithm(HashAlgorithm.sha1,
                    SignatureAlgorithm.dsa));

                clientExtensions = TlsExtensionsUtils.EnsureExtensionsInitialised(clientExtensions);

                TlsUtilities.AddSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
            }

            if (TlsECCUtils.ContainsECCCipherSuites( this.GetCipherSuites()))
            {
                /*
                 * RFC 4492 5.1. A client that proposes ECC cipher suites in its ClientHello message
                 * appends these extensions (along with any others), enumerating the curves it supports
                 * and the point formats it can parse. Clients SHOULD send both the Supported Elliptic
                 * Curves Extension and the Supported Point Formats Extension.
                 */
                /*
                 * TODO Could just add all the curves since we support them all, but users may not want
                 * to use unnecessarily large fields. Need configuration options.
                 */
                this.namedCurves = new NamedCurve[]{NamedCurve.secp256r1, NamedCurve.sect233r1, NamedCurve.secp224r1,
                NamedCurve.sect193r1, NamedCurve.secp192r1, NamedCurve.arbitrary_explicit_char2_curves,
                NamedCurve.arbitrary_explicit_prime_curves};
                this.clientECPointFormats = new ECPointFormat[]{ ECPointFormat.ansiX962_compressed_char2,
                           ECPointFormat.ansiX962_compressed_prime, ECPointFormat.uncompressed};

                if (clientExtensions == null)
                {
                    clientExtensions = new Hashtable();
                }

                TlsECCUtils.AddSupportedEllipticCurvesExtension(clientExtensions, namedCurves);
                TlsECCUtils.AddSupportedPointFormatsExtension(clientExtensions, clientECPointFormats);
            }

            return clientExtensions;
        }

        public virtual ProtocolVersion MinimumVersion
        {
            get
            {
                return ProtocolVersion.TLSv10;
            }
        }

        public virtual void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            if (!MinimumVersion.IsEqualOrEarlierVersionOf(serverVersion))
            {
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }
        }

        public virtual CompressionMethod[] GetCompressionMethods()
        {
            return new CompressionMethod[] { CompressionMethod.NULL };
        }

        public virtual void NotifySessionID(byte[] sessionID)
        {
            // Currently ignored
        }

        public virtual void NotifySelectedCipherSuite(CipherSuite selectedCipherSuite)
        {
            this.selectedCipherSuite = selectedCipherSuite;
        }

        public virtual void NotifySelectedCompressionMethod(CompressionMethod selectedCompressionMethod)
        {
            this.selectedCompressionMethod = selectedCompressionMethod;
        }

        public virtual void ProcessServerExtensions(IDictionary serverExtensions)
        {
            /*
             * TlsProtocol implementation validates that any server extensions received correspond to
             * client extensions sent. By default, we don't send any, and this method is not called.
             */
            if (serverExtensions != null)
            {
                /*
                 * RFC 5246 7.4.1.4.1. Servers MUST NOT send this extension.
                 */
                if (serverExtensions.Contains(TlsUtilities.EXT_signature_algorithms))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
                                
                NamedCurve[]  namedCurves = TlsECCUtils.GetSupportedEllipticCurvesExtension(serverExtensions);

                if (namedCurves != null)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                this.serverECPointFormats = TlsECCUtils.GetSupportedPointFormatsExtension(serverExtensions);

                if (this.serverECPointFormats != null && !TlsECCUtils.IsECCCipherSuite(this.selectedCipherSuite))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
        }

        public virtual void ProcessServerSupplementalData(IList serverSupplementalData)
        {
            if (serverSupplementalData != null)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        public virtual IList GetClientSupplementalData()
        {
            return null;
        }

        public override TlsCompression GetCompression()
        {
            switch (selectedCompressionMethod)
            {
                case CompressionMethod.NULL:
                    return new TlsNullCompression();

                default:
                    /*
                     * Note: internal error here; the TlsProtocol implementation verifies that the
                     * server-selected compression method was in the list of client-offered compression
                     * methods, so if we now can't produce an implementation, we shouldn't have offered it!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public virtual void NotifyNewSessionTicket(NewSessionTicket newSessionTicket)
        {

        }
               
        public abstract CipherSuite[] GetCipherSuites();

        public abstract TlsKeyExchange GetKeyExchange();

        public abstract TlsAuthentication GetAuthentication();
        
    }
}