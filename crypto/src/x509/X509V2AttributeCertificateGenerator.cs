using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.X509
{
    /// <remarks>Class to produce an X.509 Version 2 AttributeCertificate.</remarks>
    public class X509V2AttributeCertificateGenerator
    {
        private readonly X509ExtensionsGenerator m_extGenerator = new X509ExtensionsGenerator();

        private V2AttributeCertificateInfoGenerator m_acInfoGen;

        public X509V2AttributeCertificateGenerator()
        {
            m_acInfoGen = new V2AttributeCertificateInfoGenerator();
        }

        /// <summary>Reset the generator</summary>
        public void Reset()
        {
            m_acInfoGen = new V2AttributeCertificateInfoGenerator();
            m_extGenerator.Reset();
        }

        /// <summary>Set the Holder of this Attribute Certificate.</summary>
        public void SetHolder(AttributeCertificateHolder holder)
        {
            m_acInfoGen.SetHolder(holder.m_holder);
        }

        /// <summary>Set the issuer.</summary>
        public void SetIssuer(AttributeCertificateIssuer issuer)
        {
            m_acInfoGen.SetIssuer(AttCertIssuer.GetInstance(issuer.form));
        }

        /// <summary>Set the serial number for the certificate.</summary>
        public void SetSerialNumber(BigInteger serialNumber)
        {
            m_acInfoGen.SetSerialNumber(new DerInteger(serialNumber));
        }

        public void SetNotBefore(DateTime date)
        {
            m_acInfoGen.SetStartDate(Rfc5280Asn1Utilities.CreateGeneralizedTime(date));
        }

        public void SetNotAfter(DateTime date)
        {
            m_acInfoGen.SetEndDate(Rfc5280Asn1Utilities.CreateGeneralizedTime(date));
        }

        /// <summary>Add an attribute.</summary>
        public void AddAttribute(X509Attribute attribute)
        {
            m_acInfoGen.AddAttribute(AttributeX509.GetInstance(attribute.ToAsn1Object()));
        }

        public void SetIssuerUniqueId(bool[] iui)
        {
            m_acInfoGen.SetIssuerUniqueID(X509V3CertificateGenerator.BooleanToBitString(iui));
        }

        /// <summary>Add a given extension field for the standard extensions tag.</summary>
        public void AddExtension(string oid, bool critical, Asn1Encodable extensionValue)
        {
            m_extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);
        }

        /// <summary>
        /// Add a given extension field for the standard extensions tag.
        /// The value parameter becomes the contents of the octet string associated
        /// with the extension.
        /// </summary>
        public void AddExtension(string oid, bool critical, byte[] extensionValue)
        {
            m_extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);
        }

        /// <summary>
        /// Generate a new <see cref="X509V2AttributeCertificate"/> using the provided <see cref="ISignatureFactory"/>.
        /// </summary>
        /// <param name="signatureFactory">A <see cref="ISignatureFactory">signature factory</see> with the necessary
        /// algorithm details.</param>
        /// <returns>An <see cref="X509V2AttributeCertificate"/>.</returns>
        public X509V2AttributeCertificate Generate(ISignatureFactory signatureFactory)
        {
            var sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

            m_acInfoGen.SetSignature(sigAlgID);

            if (!m_extGenerator.IsEmpty)
            {
                m_acInfoGen.SetExtensions(m_extGenerator.Generate());
            }

            var acInfo = m_acInfoGen.GenerateAttributeCertificateInfo();

            var signature = X509Utilities.GenerateSignature(signatureFactory, acInfo);

            return new X509V2AttributeCertificate(new AttributeCertificate(acInfo, sigAlgID, signature));
        }

        /// <summary>
        /// Allows enumeration of the signature names supported by the generator.
        /// </summary>
        [Obsolete("Will be removed")]
        public IEnumerable<string> SignatureAlgNames => X509Utilities.GetAlgNames();
    }
}
