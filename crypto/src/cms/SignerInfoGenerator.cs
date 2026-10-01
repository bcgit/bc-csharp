using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Pre-configured CMS <c>SignerInfo</c> for signed-data creation. Build with
    /// <see cref="SignerInfoGeneratorBuilder"/>, then pass to
    /// <see cref="CmsSignedDataGenerator.AddSignerInfoGenerator"/>.
    /// </summary>
    public class SignerInfoGenerator
    {
        private readonly SignerIdentifier m_sigID;
        private readonly ISignatureFactory m_signatureFactory;
        private readonly CmsAttributeTableGenerator m_signedGen;
        private readonly CmsAttributeTableGenerator m_unsignedGen;
        private readonly X509Certificate m_certificate;

        internal SignerInfoGenerator(SignerIdentifier sigID, ISignatureFactory signatureFactory,
            CmsAttributeTableGenerator signedGen, CmsAttributeTableGenerator unsignedGen, X509Certificate certificate)
        {
            m_sigID = sigID;
            m_signatureFactory = signatureFactory;
            m_signedGen = signedGen;
            m_unsignedGen = unsignedGen;
            m_certificate = certificate;
        }

        /// <summary>Gets the signer's X.509 certificate when built with one, otherwise null.</summary>
        public X509Certificate Certificate => m_certificate;

        /// <summary>Gets the SignerInfo version that will be generated (1 or 3).</summary>
        public int GeneratedVersion => m_sigID.IsTagged ? 3 : 1;

        /// <summary>Returns a builder pre-populated with this generator's attribute settings.</summary>
        /// <returns>A new <see cref="SignerInfoGeneratorBuilder"/>.</returns>
        public SignerInfoGeneratorBuilder NewBuilder()
        {
            SignerInfoGeneratorBuilder builder = new SignerInfoGeneratorBuilder();
            builder.WithSignedAttributeGenerator(m_signedGen);
            builder.WithUnsignedAttributeGenerator(m_unsignedGen);
            builder.SetDirectSignature(hasNoSignedAttributes: m_signedGen == null);
            return builder;
        }

        /// <summary>Gets the signature factory used to produce the SignerInfo signature value.</summary>
        public ISignatureFactory SignatureFactory => m_signatureFactory;

        /// <summary>Gets the signed-attribute generator, or null for a direct signature over the content.</summary>
        public CmsAttributeTableGenerator SignedAttributeTableGenerator => m_signedGen;

        /// <summary>Gets the signer identifier (issuer/serial or subject key identifier).</summary>
        public SignerIdentifier SignerID => m_sigID;

        /// <summary>Gets the unsigned-attribute generator, if any.</summary>
        public CmsAttributeTableGenerator UnsignedAttributeTableGenerator => m_unsignedGen;
    }

    /// <summary>Builds <see cref="SignerInfoGenerator"/> instances for CMS SignedData creation.</summary>
    /// <remarks>
    /// Use <see cref="SetDirectSignature"/> for a signature over the raw content. Otherwise, a null
    /// signed-attribute generator selects <see cref="DefaultSignedAttributeTableGenerator"/>.
    /// </remarks>
    public class SignerInfoGeneratorBuilder
    {
        private bool m_directSignature;
        private CmsAttributeTableGenerator m_signedGen;
        private CmsAttributeTableGenerator m_unsignedGen;

        /// <summary>Initialises a builder with default signed-attribute generation.</summary>
        public SignerInfoGeneratorBuilder()
        {
        }

        /// <summary>
        /// When <paramref name="hasNoSignedAttributes"/> is true, the signature is computed over the content only and
        /// no signed or unsigned attributes are included.
        /// </summary>
        /// <param name="hasNoSignedAttributes">Whether to omit signed attributes (direct signature).</param>
        /// <returns>This builder.</returns>
        public SignerInfoGeneratorBuilder SetDirectSignature(bool hasNoSignedAttributes)
        {
            m_directSignature = hasNoSignedAttributes;
            return this;
        }

        /// <summary>Sets a custom generator for signed attributes.</summary>
        /// <param name="signedGen">The signed-attribute generator, or null to use the default.</param>
        /// <returns>This builder.</returns>
        public SignerInfoGeneratorBuilder WithSignedAttributeGenerator(CmsAttributeTableGenerator signedGen)
        {
            m_signedGen = signedGen;
            return this;
        }

        /// <summary>Sets a generator for unsigned attributes.</summary>
        /// <param name="unsignedGen">The unsigned-attribute generator.</param>
        /// <returns>This builder.</returns>
        public SignerInfoGeneratorBuilder WithUnsignedAttributeGenerator(CmsAttributeTableGenerator unsignedGen)
        {
            m_unsignedGen = unsignedGen;
            return this;
        }

        /// <summary>
        /// Builds a generator that identifies the signer by X.509 issuer and serial number from
        /// <paramref name="certificate"/>.
        /// </summary>
        /// <param name="contentSigner">The signature factory for the SignerInfo signature value.</param>
        /// <param name="certificate">The signer's X.509 certificate.</param>
        /// <returns>A configured <see cref="SignerInfoGenerator"/>.</returns>
        // TODO[api] 'contentSigner' => 'signatureFactory'
        public SignerInfoGenerator Build(ISignatureFactory contentSigner, X509Certificate certificate)
        {
            SignerIdentifier sigID = CmsUtilities.GetSignerIdentifier(certificate);

            return CreateGenerator(contentSigner, sigID, certificate);
        }

        /// <summary>
        /// Builds a generator that identifies the signer by subject key identifier. The identifier should follow RFC
        /// 5280 section 4.2.1.2 where possible.
        /// </summary>
        /// <param name="signerFactory">The signature factory for the SignerInfo signature value.</param>
        /// <param name="subjectKeyIdentifier">The key identifier for the verifying public key.</param>
        /// <returns>A configured <see cref="SignerInfoGenerator"/>.</returns>
        // TODO[api] 'signerFactory' => 'signatureFactory'
        public SignerInfoGenerator Build(ISignatureFactory signerFactory, byte[] subjectKeyIdentifier)
        {
            SignerIdentifier sigID = CmsUtilities.GetSignerIdentifier(subjectKeyIdentifier);

            return CreateGenerator(signerFactory, sigID, certificate: null);
        }

        private SignerInfoGenerator CreateGenerator(ISignatureFactory signatureFactory, SignerIdentifier sigID,
            X509Certificate certificate)
        {
            CmsAttributeTableGenerator signedGen = m_signedGen;
            CmsAttributeTableGenerator unsignedGen = m_unsignedGen;

            if (m_directSignature)
            {
                signedGen = null;
                unsignedGen = null;
            }
            else if (signedGen == null)
            {
                signedGen = new DefaultSignedAttributeTableGenerator();
            }

            return new SignerInfoGenerator(sigID, signatureFactory, signedGen, unsignedGen, certificate);
        }
    }
}
