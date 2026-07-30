using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Streaming parser for CMS AuthenticatedData messages, the counterpart to <see cref="CmsAuthenticatedData"/>.
    /// In streaming mode only one recipient can be tried and parser methods must be called in order.
    /// </summary>
    /// <remarks>
    /// The constructor reads only enough of the supplied stream to expose CMS structure metadata (originator
    /// info, recipient infos, MAC algorithm). Encapsulated content is drained lazily via
    /// <see cref="RecipientInformation.GetContentStream(Org.BouncyCastle.Crypto.ICipherParameters)"/>.
    /// The MAC is available from <see cref="GetMac()"/> once the content stream has been read to end-of-file.
    /// <para>The supplied stream is not closed automatically. Dispose this parser to close the underlying stream,
    /// or close it yourself.</para>
    /// <para>This class does not introduce buffering. For large inputs, pass a buffered stream with a suitably
    /// large buffer size.</para>
    /// <para>Example:</para>
    /// <code>
    /// CmsAuthenticatedDataParser ad = new CmsAuthenticatedDataParser(inputStream);
    /// RecipientInformationStore recipients = ad.GetRecipientInfos();
    /// foreach (RecipientInformation recipient in recipients)
    /// {
    ///     using CmsTypedStream recData = recipient.GetContentStream(privateKey);
    ///     ProcessDataStream(recData.ContentStream);
    ///     if (!Arrays.FixedTimeEquals(ad.GetMac(), recipient.GetMac()))
    ///     {
    ///         // MAC mismatch
    ///     }
    /// }
    /// </code>
    /// </remarks>
    public class CmsAuthenticatedDataParser
        : CmsContentInfoParser
    {
        internal RecipientInformationStore _recipientInfoStore;
        internal AuthenticatedDataParser authData;

        private AlgorithmIdentifier macAlg;
        private byte[] mac;
        private Asn1.Cms.AttributeTable authAttrs;
        private Asn1.Cms.AttributeTable unauthAttrs;

        private bool authAttrNotRead;
        private bool unauthAttrNotRead;
        private OriginatorInformation m_originatorInformation;

        /// <summary>Creates a parser from an encoded AuthenticatedData message.</summary>
        /// <param name="envelopedData">The DER-encoded CMS ContentInfo bytes.</param>
        // TODO[api] Rename parameter to 'authenticatedData'
        public CmsAuthenticatedDataParser(byte[] envelopedData)
            : this(new MemoryStream(envelopedData, false))
        {
        }

        /// <summary>Creates a parser from an encoded AuthenticatedData message.</summary>
        /// <param name="envelopedData">The stream containing the DER-encoded CMS ContentInfo.</param>
        /// <exception cref="System.ArgumentNullException"><paramref name="envelopedData"/> is null.</exception>
        /// <exception cref="CmsException">The stream cannot be parsed as CMS ContentInfo.</exception>
        // TODO[api] Rename parameter to 'authenticatedData'
        public CmsAuthenticatedDataParser(Stream envelopedData)
            : base(envelopedData)
        {
            this.authAttrNotRead = true;
            this.authData = new AuthenticatedDataParser(
                (Asn1SequenceParser)contentInfo.GetContent(Asn1Tags.Sequence));

            // TODO Validate version?
            //DerInteger version = this.authData.getVersion();

            var originatorInfo = authData.GetOriginatorInfo();
            m_originatorInformation = originatorInfo == null ? null : new OriginatorInformation(originatorInfo);

            //
            // read the recipients
            //
            Asn1Set recipientInfos = Asn1Set.GetInstance(authData.GetRecipientInfos().ToAsn1Object());

            this.macAlg = authData.GetMacAlgorithm();

            //
            // read the authenticated content info
            //
            ContentInfoParser data = authData.GetEnapsulatedContentInfo();
            CmsReadable readable = new CmsProcessableInputStream(
                ((Asn1OctetStringParser)data.GetContent(Asn1Tags.OctetString)).GetOctetStream());
            CmsSecureReadable secureReadable = new CmsEnvelopedHelper.CmsAuthenticatedSecureReadable(
                this.macAlg, readable);

            //
            // build the RecipientInformationStore
            //
            this._recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(
                recipientInfos, secureReadable);
        }

        /// <summary>Gets originator certificates and CRLs carried in the message, or null if absent.</summary>
        public OriginatorInformation OriginatorInformation => m_originatorInformation;

        /// <summary>Gets the MAC algorithm identifier.</summary>
        public AlgorithmIdentifier MacAlgorithmID => macAlg;

        /// <summary>Return the object identifier for the MAC algorithm.</summary>
        public string MacAlgOid => macAlg.Algorithm.GetID();

        /// <summary>Return the ASN.1 encoded MAC algorithm parameters, or null if there aren't any.</summary>
        public Asn1Object MacAlgParams => macAlg.Parameters?.ToAsn1Object();

        /// <summary>Returns a store of the intended recipients for this message.</summary>
        public RecipientInformationStore GetRecipientInfos() => _recipientInfoStore;

        /// <summary>
        /// Returns a copy of the message authentication code. Call after the encapsulated content stream has been
        /// read to end-of-file.
        /// </summary>
        public byte[] GetMac()
        {
            if (mac == null)
            {
                GetAuthAttrs();
                mac = authData.GetMac().GetOctets();
            }
            return Arrays.Clone(mac);
        }

        /// <summary>Returns a table of authenticated attributes indexed by attribute OID, or null if absent.</summary>
        public Asn1.Cms.AttributeTable GetAuthAttrs()
        {
            if (authAttrs == null && authAttrNotRead)
            {
                Asn1SetParser s = authData.GetAuthAttrs();

                authAttrNotRead = false;

                if (s != null)
                {
                    authAttrs = CmsUtilities.ParseAttributeTable(s);
                }
            }

            return authAttrs;
        }

        /// <summary>
        /// Returns a table of unauthenticated attributes indexed by attribute OID, or null if absent.
        /// </summary>
        public Asn1.Cms.AttributeTable GetUnauthAttrs()
        {
            if (unauthAttrs == null && unauthAttrNotRead)
            {
                Asn1SetParser s = authData.GetUnauthAttrs();

                unauthAttrNotRead = false;

                if (s != null)
                {
                    unauthAttrs = CmsUtilities.ParseAttributeTable(s);
                }
            }

            return unauthAttrs;
        }
    }
}
