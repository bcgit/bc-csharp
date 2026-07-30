using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Streaming parser for CMS EnvelopedData messages, the counterpart to <see cref="CmsEnvelopedData"/>.
    /// In streaming mode only one recipient can be tried and parser methods must be called in order.
    /// </summary>
    /// <remarks>
    /// The constructor reads only enough of the supplied stream to expose CMS structure metadata (originator
    /// info, recipient infos, content-encryption algorithm). Encrypted content is drained lazily via
    /// <see cref="RecipientInformation.GetContentStream(Org.BouncyCastle.Crypto.ICipherParameters)"/> or
    /// <see cref="RecipientInformation.GetContent(Org.BouncyCastle.Crypto.ICipherParameters)"/>.
    /// <para>The supplied stream is not closed automatically. Dispose this parser to close the underlying stream,
    /// or close it yourself.</para>
    /// <para>This class does not introduce buffering. For large inputs, pass a buffered stream with a suitably
    /// large buffer size.</para>
    /// <para>Example:</para>
    /// <code>
    /// CmsEnvelopedDataParser ep = new CmsEnvelopedDataParser(inputStream);
    /// RecipientInformationStore recipients = ep.GetRecipientInfos();
    /// foreach (RecipientInformation recipient in recipients)
    /// {
    ///     using CmsTypedStream recData = recipient.GetContentStream(privateKey);
    ///     ProcessDataStream(recData.ContentStream);
    /// }
    /// </code>
    /// </remarks>
    public class CmsEnvelopedDataParser
        : CmsContentInfoParser
    {
        internal RecipientInformationStore recipientInfoStore;
        internal EnvelopedDataParser envelopedData;

        private AlgorithmIdentifier _encAlg;
        private Asn1.Cms.AttributeTable _unprotectedAttributes;
        private bool _attrNotRead;
        private OriginatorInformation m_originatorInformation;

        /// <summary>Creates a parser from an encoded EnvelopedData message.</summary>
        /// <param name="envelopedData">The DER-encoded CMS ContentInfo bytes.</param>
        public CmsEnvelopedDataParser(byte[] envelopedData)
            : this(new MemoryStream(envelopedData, false))
        {
        }

        /// <summary>Creates a parser from an encoded EnvelopedData message.</summary>
        /// <param name="envelopedData">The stream containing the DER-encoded CMS ContentInfo.</param>
        /// <exception cref="System.ArgumentNullException"><paramref name="envelopedData"/> is null.</exception>
        /// <exception cref="CmsException">The stream cannot be parsed as CMS ContentInfo.</exception>
        public CmsEnvelopedDataParser(Stream envelopedData)
            : base(envelopedData)
        {
            this._attrNotRead = true;
            this.envelopedData = new EnvelopedDataParser(
                (Asn1SequenceParser)this.contentInfo.GetContent(Asn1Tags.Sequence));

            // TODO Validate version?
            //DerInteger version = this.envelopedData.Version;

            var originatorInfo = this.envelopedData.GetOriginatorInfo();
            m_originatorInformation = originatorInfo == null ? null : new OriginatorInformation(originatorInfo);

            //
            // read the recipients
            //
            Asn1Set recipientInfos = Asn1Set.GetInstance(this.envelopedData.GetRecipientInfos().ToAsn1Object());

            //
            // read the encrypted content info
            //
            EncryptedContentInfoParser encInfo = this.envelopedData.GetEncryptedContentInfo();
            this._encAlg = encInfo.ContentEncryptionAlgorithm;
            CmsReadable readable = new CmsProcessableInputStream(
                ((Asn1OctetStringParser)encInfo.GetEncryptedContent(Asn1Tags.OctetString)).GetOctetStream());
            CmsSecureReadable secureReadable = new CmsEnvelopedHelper.CmsEnvelopedSecureReadable(
                this._encAlg, readable);

            //
            // build the RecipientInformationStore
            //
            this.recipientInfoStore = CmsEnvelopedHelper.BuildRecipientInformationStore(
                recipientInfos, secureReadable);
        }

        /// <summary>Gets the content-encryption algorithm identifier.</summary>
        public AlgorithmIdentifier EncryptionAlgorithmID => _encAlg;

        /// <summary>Return the object identifier for the content-encryption algorithm.</summary>
        public string EncryptionAlgOid => _encAlg.Algorithm.GetID();

        /// <summary>
        /// Return the ASN.1 encoded content-encryption algorithm parameters, or null if there aren't any.
        /// </summary>
        public Asn1Object EncryptionAlgParams => _encAlg.Parameters?.ToAsn1Object();

        /// <summary>Gets originator certificates and CRLs carried in the message, or null if absent.</summary>
        public OriginatorInformation OriginatorInformation => m_originatorInformation;

        /// <summary>Returns a store of the intended recipients for this message.</summary>
        public RecipientInformationStore GetRecipientInfos() => this.recipientInfoStore;

        /// <summary>Returns a table of unprotected attributes indexed by attribute OID, or null if absent.</summary>
        public Asn1.Cms.AttributeTable GetUnprotectedAttributes()
        {
            if (_unprotectedAttributes == null && _attrNotRead)
            {
                Asn1SetParser asn1Set = this.envelopedData.GetUnprotectedAttrs();

                _attrNotRead = false;

                if (asn1Set != null)
                {
                    _unprotectedAttributes = CmsUtilities.ParseAttributeTable(asn1Set);
                }
            }

            return _unprotectedAttributes;
        }
    }
}
