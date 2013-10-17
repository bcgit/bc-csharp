using System.Collections;
namespace Org.BouncyCastle.Crypto.Tls
{


    public abstract class AbstractTlsServer : AbstractTlsPeer, TlsServer
    {
        protected TlsCipherFactory cipherFactory;

        protected TlsServerContext context;

        protected ProtocolVersion clientVersion;
        protected CipherSuite[] offeredCipherSuites;
        protected CompressionMethod[] offeredCompressionMethods;
        protected IDictionary clientExtensions;

        protected short maxFragmentLengthOffered = -1;
        protected bool truncatedHMacOffered;
        protected IList supportedSignatureAlgorithms;
        protected bool eccCipherSuitesOffered;
        protected NamedCurve[] namedCurves;
        protected ECPointFormat[] clientECPointFormats, serverECPointFormats;

        protected ProtocolVersion serverVersion;
        protected CipherSuite selectedCipherSuite;
        protected CompressionMethod selectedCompressionMethod;
        protected IDictionary serverExtensions;

        public AbstractTlsServer()
            : this(new DefaultTlsCipherFactory())
        {

        }

        public AbstractTlsServer(TlsCipherFactory cipherFactory)
        {
            this.cipherFactory = cipherFactory;
        }

        protected virtual bool AllowTruncatedHMac
        {
            get
            {
                return false;
            }
        }

        protected IDictionary CheckServerExtensions()
        {
            return this.serverExtensions = TlsExtensionsUtils.EnsureExtensionsInitialised(this.serverExtensions);
        }

        protected abstract CipherSuite[] CipherSuites
        {
            get;
        }

        protected virtual CompressionMethod[] GetCompressionMethods()
        {
            return new CompressionMethod[] { CompressionMethod.NULL };
        }

        protected virtual ProtocolVersion MaximumVersion
        {
            get
            {
                return ProtocolVersion.TLSv11;
            }
        }

        protected virtual ProtocolVersion MinimumVersion
        {
            get
            {
                return ProtocolVersion.TLSv10;
            }
        }

        protected bool SupportsClientECCCapabilities(NamedCurve[] namedCurves, ECPointFormat[] ecPointFormats)
        {
            // NOTE: BC supports all the current set of point formats so we don't check them here

            if (namedCurves == null)
            {
                /*
                 * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
                 * extensions. In this case, the server is free to choose any one of the elliptic curves
                 * or point formats [...].
                 */
                return TlsECCUtils.HasAnySupportedNamedCurves();
            }

            for (int i = 0; i < namedCurves.Length; ++i)
            {
                NamedCurve namedCurve = namedCurves[i];
                if (!NamedCurveHelper.RefersToASpecificNamedCurve(namedCurve) || TlsECCUtils.IsSupportedNamedCurve(namedCurve))
                {
                    return true;
                }
            }

            return false;
        }

        public virtual void Init(TlsServerContext context)
        {
            this.context = context;
        }

        public virtual void NotifyClientVersion(ProtocolVersion clientVersion)
        {
            this.clientVersion = clientVersion;
        }

        public virtual void NotifyOfferedCipherSuites(CipherSuite[] offeredCipherSuites)
        {
            this.offeredCipherSuites = offeredCipherSuites;
            this.eccCipherSuitesOffered = TlsECCUtils.ContainsECCCipherSuites(this.offeredCipherSuites);
        }

        public virtual void NotifyOfferedCompressionMethods(CompressionMethod[] offeredCompressionMethods)
        {
            this.offeredCompressionMethods = offeredCompressionMethods;
        }

        public virtual void ProcessClientExtensions(IDictionary clientExtensions)
        {
            this.clientExtensions = clientExtensions;

            if (clientExtensions != null)
            {
                this.maxFragmentLengthOffered = TlsExtensionsUtils.GetMaxFragmentLengthExtension(clientExtensions);
                this.truncatedHMacOffered = TlsExtensionsUtils.HasTruncatedHMacExtension(clientExtensions);

                this.supportedSignatureAlgorithms = TlsUtilities.GetSignatureAlgorithmsExtension(clientExtensions);
                if (this.supportedSignatureAlgorithms != null)
                {
                    /*
                     * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
                     * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
                     */
                    if (!TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(clientVersion))
                    {
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }
                }

                this.namedCurves = TlsECCUtils.GetSupportedEllipticCurvesExtension(clientExtensions);
                this.clientECPointFormats = TlsECCUtils.GetSupportedPointFormatsExtension(clientExtensions);
            }

            /*
             * RFC 4429 4. The client MUST NOT include these extensions in the ClientHello message if it
             * does not propose any ECC cipher suites.
             */
            if (!this.eccCipherSuitesOffered && (this.namedCurves != null || this.clientECPointFormats != null))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        public virtual ProtocolVersion ServerVersion
        {
            get
            {
                if (MinimumVersion.IsEqualOrEarlierVersionOf(clientVersion))
                {
                    ProtocolVersion maximumVersion = MaximumVersion;
                    if (clientVersion.IsEqualOrEarlierVersionOf(maximumVersion))
                    {
                        return serverVersion = clientVersion;
                    }
                    if (clientVersion.IsLaterVersionOf(maximumVersion))
                    {
                        return serverVersion = maximumVersion;
                    }
                }
                throw new TlsFatalAlert(AlertDescription.protocol_version);
            }
        }

        public virtual CipherSuite SelectedCipherSuite
        {
            get
            {
                /*
                 * TODO RFC 5246 7.4.3. In order to negotiate correctly, the server MUST check any candidate
                 * cipher suites against the "signature_algorithms" extension before selecting them. This is
                 * somewhat inelegant but is a compromise designed to minimize changes to the original
                 * cipher suite design.
                 */

                /*
                 * RFC 4429 5.1. A server that receives a ClientHello containing one or both of these
                 * extensions MUST use the client's enumerated capabilities to guide its selection of an
                 * appropriate cipher suite. One of the proposed ECC cipher suites must be negotiated only
                 * if the server can successfully complete the handshake while using the curves and point
                 * formats supported by the client [...].
                 */
                bool eccCipherSuitesEnabled = SupportsClientECCCapabilities(this.namedCurves, this.clientECPointFormats);

                CipherSuite[] cipherSuites = CipherSuites;
                for (int i = 0; i < cipherSuites.Length; ++i)
                {
                    CipherSuite cipherSuite = cipherSuites[i];
                    if (TlsProtocol.ArrayContains(this.offeredCipherSuites, cipherSuite)
                        && (eccCipherSuitesEnabled || !TlsECCUtils.IsECCCipherSuite(cipherSuite)))
                    {
                        return this.selectedCipherSuite = cipherSuite;
                    }
                }
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }

        public virtual CompressionMethod SelectedCompressionMethod
        {
            get
            {
                CompressionMethod[] compressionMethods = GetCompressionMethods();
                for (int i = 0; i < compressionMethods.Length; ++i)
                {
                    if (TlsProtocol.ArrayContains(offeredCompressionMethods, compressionMethods[i]))
                    {
                        return this.selectedCompressionMethod = compressionMethods[i];
                    }
                }
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }

        // Hashtable is (Integer -> byte[])
        public IDictionary GetServerExtensions()
        {
            if (this.maxFragmentLengthOffered >= 0)
            {
                TlsExtensionsUtils.AddMaxFragmentLengthExtension(CheckServerExtensions(), this.maxFragmentLengthOffered);
            }

            if (this.truncatedHMacOffered && AllowTruncatedHMac)
            {
                TlsExtensionsUtils.AddTruncatedHMacExtension(CheckServerExtensions());
            }

            if (this.clientECPointFormats != null && TlsECCUtils.IsECCCipherSuite(this.selectedCipherSuite))
            {
                /*
                 * RFC 4492 5.2. A server that selects an ECC cipher suite in response to a ClientHello
                 * message including a Supported Point Formats Extension appends this extension (along
                 * with others) to its ServerHello message, enumerating the point formats it can parse.
                 */
                this.serverECPointFormats = new ECPointFormat[]{ ECPointFormat.ansiX962_compressed_char2, 
                                                                 ECPointFormat.ansiX962_compressed_prime, 
                                                                 ECPointFormat.uncompressed };

                TlsECCUtils.AddSupportedPointFormatsExtension(CheckServerExtensions(), serverECPointFormats);
            }

            return serverExtensions;
        }

        public virtual IList GetServerSupplementalData()
        {
            return null;
        }

        public virtual CertificateStatus CertificateStatus
        {
            get
            {
                return null;
            }
        }

        public virtual CertificateRequest GetCertificateRequest()
        {
            return null;
        }

        public virtual void ProcessClientSupplementalData(IList clientSupplementalData)
        {
            if (clientSupplementalData != null)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        public virtual void NotifyClientCertificate(Certificate clientCertificate)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public override TlsCompression GetCompression()
        {
            switch (selectedCompressionMethod)
            {
                case CompressionMethod.NULL:
                    return new TlsNullCompression();

                default:
                    /*
                     * Note: internal error here; we selected the compression method, so if we now can't
                     * produce an implementation, we shouldn't have chosen it!
                     */
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public NewSessionTicket GetNewSessionTicket()
        {
            /*
             * RFC 5077 3.3. If the server determines that it does not want to include a ticket after it
             * has included the SessionTicket extension in the ServerHello, then it sends a zero-length
             * ticket in the NewSessionTicket handshake message.
             */
            return new NewSessionTicket(0L, TlsUtilities.EMPTY_BYTES);
        }

        public abstract TlsCredentials Credentials
        {
            get;
        }

        public abstract TlsKeyExchange GetKeyExchange();
    }
}