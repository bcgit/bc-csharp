using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    public class SignerInfoGenerator
    {
        private readonly SignerIdentifier m_sigID;
        private readonly ISignatureFactory m_signatureFactory;
        private readonly CmsAttributeTableGenerator m_signedGen;
        private readonly CmsAttributeTableGenerator m_unsignedGen;
        private readonly X509Certificate m_certificate;

        internal SignerInfoGenerator(SignerIdentifier sigID, ISignatureFactory signatureFactory, bool isDirectSignature,
            CmsAttributeTableGenerator signedGen, CmsAttributeTableGenerator unsignedGen, X509Certificate certificate)
        {
            m_sigID = sigID;
            m_signatureFactory = signatureFactory;
            m_signedGen = signedGen;
            m_unsignedGen = unsignedGen;
            m_certificate = certificate;
        }

        public X509Certificate Certificate => m_certificate;

        public SignerInfoGeneratorBuilder NewBuilder()
        {
            SignerInfoGeneratorBuilder builder = new SignerInfoGeneratorBuilder();
            builder.WithSignedAttributeGenerator(m_signedGen);
            builder.WithUnsignedAttributeGenerator(m_unsignedGen);
            builder.SetDirectSignature(hasNoSignedAttributes: m_signedGen == null);
            return builder;
        }

        public ISignatureFactory SignatureFactory => m_signatureFactory;

        public CmsAttributeTableGenerator SignedAttributeTableGenerator => m_signedGen;

        public SignerIdentifier SignerID => m_sigID;

        public CmsAttributeTableGenerator UnsignedAttributeTableGenerator => m_unsignedGen;
    }

    public class SignerInfoGeneratorBuilder
    {
        private bool m_directSignature;
        private CmsAttributeTableGenerator m_signedGen;
        private CmsAttributeTableGenerator m_unsignedGen;

        public SignerInfoGeneratorBuilder()
        {
        }

        /**
         * If the passed in flag is true, the signer signature will be based on the data, not
         * a collection of signed attributes, and no signed attributes will be included.
         *
         * @return the builder object
         */
        public SignerInfoGeneratorBuilder SetDirectSignature(bool hasNoSignedAttributes)
        {
            m_directSignature = hasNoSignedAttributes;
            return this;
        }

        /**
         *  Provide a custom signed attribute generator.
         *
         * @param signedGen a generator of signed attributes.
         * @return the builder object
         */
        public SignerInfoGeneratorBuilder WithSignedAttributeGenerator(CmsAttributeTableGenerator signedGen)
        {
            m_signedGen = signedGen;
            return this;
        }

        /**
         * Provide a generator of unsigned attributes.
         *
         * @param unsignedGen  a generator for signed attributes.
         * @return the builder object
         */
        public SignerInfoGeneratorBuilder WithUnsignedAttributeGenerator(CmsAttributeTableGenerator unsignedGen)
        {
            m_unsignedGen = unsignedGen;
            return this;
        }

        /**
         * Build a generator with the passed in X.509 certificate issuer and serial number as the signerIdentifier.
         *
         * @param contentSigner  operator for generating the final signature in the SignerInfo with.
         * @param certificate  X.509 certificate related to the contentSigner.
         * @return  a SignerInfoGenerator
         * @throws OperatorCreationException   if the generator cannot be built.
         */
        // TODO[api] 'contentSigner' => 'signatureFactory'
        public SignerInfoGenerator Build(ISignatureFactory contentSigner, X509Certificate certificate)
        {
            SignerIdentifier sigID = CmsUtilities.GetSignerIdentifier(certificate);

            return CreateGenerator(contentSigner, sigID, certificate);
        }

        /**
         * Build a generator with the passed in subjectKeyIdentifier as the signerIdentifier. If used  you should
         * try to follow the calculation described in RFC 5280 section 4.2.1.2.
         *
         * @param signerFactory  operator factory for generating the final signature in the SignerInfo with.
         * @param subjectKeyIdentifier    key identifier to identify the public key for verifying the signature.
         * @return  a SignerInfoGenerator
         */
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

            return new SignerInfoGenerator(sigID, signatureFactory, m_directSignature, signedGen, unsignedGen,
                certificate);
        }
    }
}
