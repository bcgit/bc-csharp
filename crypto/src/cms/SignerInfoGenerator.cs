using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    public class SignerInfoGenerator
    {
        internal readonly SignerIdentifier sigID;
        internal readonly ISignatureFactory contentSigner;
        internal readonly CmsAttributeTableGenerator signedGen;
        internal readonly CmsAttributeTableGenerator unsignedGen;
        internal readonly X509Certificate certificate;

        internal SignerInfoGenerator(SignerIdentifier sigID, ISignatureFactory contentSigner, bool isDirectSignature,
            CmsAttributeTableGenerator signedGen, CmsAttributeTableGenerator unsignedGen, X509Certificate certificate)
        {
            this.sigID = sigID;
            this.contentSigner = contentSigner;
            this.signedGen = signedGen;
            this.unsignedGen = unsignedGen;
            this.certificate = certificate;
        }

        public SignerInfoGeneratorBuilder NewBuilder()
        {
            SignerInfoGeneratorBuilder builder = new SignerInfoGeneratorBuilder();
            builder.WithSignedAttributeGenerator(signedGen);
            builder.WithUnsignedAttributeGenerator(unsignedGen);
            builder.SetDirectSignature(hasNoSignedAttributes: signedGen == null);
            return builder;
        }
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
        public SignerInfoGenerator Build(ISignatureFactory contentSigner, X509Certificate certificate)
        {
            SignerIdentifier sigID = new SignerIdentifier(new IssuerAndSerialNumber(certificate.CertificateStructure));

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
        // TODO[api] Rename 'signerFactory' to 'contentSigner' for consistency with other 'Build' method
        public SignerInfoGenerator Build(ISignatureFactory signerFactory, byte[] subjectKeyIdentifier)
        {
            SignerIdentifier sigID = new SignerIdentifier(DerOctetString.FromContents(subjectKeyIdentifier));

            return CreateGenerator(signerFactory, sigID, certificate: null);
        }

        private SignerInfoGenerator CreateGenerator(ISignatureFactory contentSigner, SignerIdentifier sigID,
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

            return new SignerInfoGenerator(sigID, contentSigner, m_directSignature, signedGen, unsignedGen,
                certificate);
        }
    }
}
