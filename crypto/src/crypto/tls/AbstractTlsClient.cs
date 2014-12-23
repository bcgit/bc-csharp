﻿using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class AbstractTlsClient
        :   AbstractTlsPeer, TlsClient
    {
        protected TlsCipherFactory mCipherFactory;

        protected TlsClientContext mContext;

        protected IList mSupportedSignatureAlgorithms;
        protected int[] mNamedCurves;
        protected byte[] mClientECPointFormats, mServerECPointFormats;

        protected int mSelectedCipherSuite;
        protected short mSelectedCompressionMethod;

        public AbstractTlsClient()
            :   this(new DefaultTlsCipherFactory())
        {
        }

        public AbstractTlsClient(TlsCipherFactory cipherFactory)
        {
            this.mCipherFactory = cipherFactory;
        }

        protected virtual bool AllowUnexpectedServerExtension(int extensionType, byte[] extensionData)
        {
            switch (extensionType)
            {
            case ExtensionType.elliptic_curves:
                /*
                 * Exception added based on field reports that some servers do send this, although the
                 * Supported Elliptic Curves Extension is clearly intended to be client-only. If
                 * present, we still require that it is a valid EllipticCurveList.
                 */
                TlsEccUtilities.ReadSupportedEllipticCurvesExtension(extensionData);
                return true;
            default:
                return false;
            }
        }

        protected virtual void CheckForUnexpectedServerExtension(IDictionary serverExtensions, int extensionType)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(serverExtensions, extensionType);
            if (extensionData != null && !AllowUnexpectedServerExtension(extensionType, extensionData))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        public virtual void Init(TlsClientContext context)
        {
            this.mContext = context;
        }

        public virtual TlsSession GetSessionToResume()
        {
            return null;
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
                // return getMinimumVersion();

                // "the value of ClientHello.client_version"
                return ClientVersion;
            }
        }

        public virtual ProtocolVersion ClientVersion
        {
            get { return ProtocolVersion.TLSv12; }
        }

        public virtual bool IsFallback
        {
            /*
             * draft-ietf-tls-downgrade-scsv-00 4. [..] is meant for use by clients that repeat a
             * connection attempt with a downgraded protocol in order to avoid interoperability problems
             * with legacy servers.
             */
            get { return false; }
        }

        public virtual IDictionary GetClientExtensions()
        {
            IDictionary clientExtensions = null;

            ProtocolVersion clientVersion = mContext.ClientVersion;

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior to 1.2.
             * Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(clientVersion))
            {
                // TODO Provide a way for the user to specify the acceptable hash/signature algorithms.

                byte[] hashAlgorithms = new byte[]{ HashAlgorithm.sha512, HashAlgorithm.sha384, HashAlgorithm.sha256,
                    HashAlgorithm.sha224, HashAlgorithm.sha1 };

                // TODO Sort out ECDSA signatures and add them as the preferred option here
                byte[] signatureAlgorithms = new byte[]{ SignatureAlgorithm.rsa };

                this.mSupportedSignatureAlgorithms = Platform.CreateArrayList();
                for (int i = 0; i < hashAlgorithms.Length; ++i)
                {
                    for (int j = 0; j < signatureAlgorithms.Length; ++j)
                    {
                        this.mSupportedSignatureAlgorithms.Add(new SignatureAndHashAlgorithm(hashAlgorithms[i],
                            signatureAlgorithms[j]));
                    }
                }

                /*
                 * RFC 5264 7.4.3. Currently, DSA [DSS] may only be used with SHA-1.
                 */
                this.mSupportedSignatureAlgorithms.Add(new SignatureAndHashAlgorithm(HashAlgorithm.sha1,
                    SignatureAlgorithm.dsa));

                clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(clientExtensions);

                TlsUtilities.AddSignatureAlgorithmsExtension(clientExtensions, mSupportedSignatureAlgorithms);
            }

            if (TlsEccUtilities.ContainsEccCipherSuites(GetCipherSuites()))
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
                this.mNamedCurves = new int[]{ NamedCurve.secp256r1, NamedCurve.secp384r1 };
                this.mClientECPointFormats = new byte[]{ ECPointFormat.uncompressed,
                    ECPointFormat.ansiX962_compressed_prime, ECPointFormat.ansiX962_compressed_char2, };

                clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(clientExtensions);

                TlsEccUtilities.AddSupportedEllipticCurvesExtension(clientExtensions, mNamedCurves);
                TlsEccUtilities.AddSupportedPointFormatsExtension(clientExtensions, mClientECPointFormats);
            }

            return clientExtensions;
        }

        public virtual ProtocolVersion MinimumVersion
        {
            get { return ProtocolVersion.TLSv10; }
        }

        public virtual void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            if (!MinimumVersion.IsEqualOrEarlierVersionOf(serverVersion))
                throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        public abstract int[] GetCipherSuites();

        public virtual byte[] GetCompressionMethods()
        {
            return new byte[]{ CompressionMethod.cls_null };
        }

        public virtual void NotifySessionID(byte[] sessionID)
        {
            // Currently ignored
        }

        public virtual void NotifySelectedCipherSuite(int selectedCipherSuite)
        {
            this.mSelectedCipherSuite = selectedCipherSuite;
        }

        public virtual void NotifySelectedCompressionMethod(byte selectedCompressionMethod)
        {
            this.mSelectedCompressionMethod = selectedCompressionMethod;
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
                CheckForUnexpectedServerExtension(serverExtensions, ExtensionType.signature_algorithms);

                CheckForUnexpectedServerExtension(serverExtensions, ExtensionType.elliptic_curves);

                if (TlsEccUtilities.IsEccCipherSuite(this.mSelectedCipherSuite))
                {
                    this.mServerECPointFormats = TlsEccUtilities.GetSupportedPointFormatsExtension(serverExtensions);
                }
                else
                {
                    CheckForUnexpectedServerExtension(serverExtensions, ExtensionType.ec_point_formats);
                }
            }
        }

        public virtual void ProcessServerSupplementalData(IList serverSupplementalData)
        {
            if (serverSupplementalData != null)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        public abstract TlsKeyExchange GetKeyExchange();

        public abstract TlsAuthentication GetAuthentication();

        public virtual IList GetClientSupplementalData()
        {
            return null;
        }

        public override TlsCompression GetCompression()
        {
            switch (mSelectedCompressionMethod)
            {
            case CompressionMethod.cls_null:
                return new TlsNullCompression();

            case CompressionMethod.DEFLATE:
                return new TlsDeflateCompression();

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
    }
}
