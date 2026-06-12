using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security.Certificates;

namespace Org.BouncyCastle.X509
{
    /// <summary>
    /// Generator for X.509 version 3 certificates as defined in RFC 5280.
    /// Builds the TBSCertificate structure, optional v3 extensions, and signs the result via
    /// <see cref="Generate(ISignatureFactory)"/>.
    /// </summary>
    public class X509V3CertificateGenerator
    {
        private readonly X509ExtensionsGenerator m_extGenerator = new X509ExtensionsGenerator();

        private V3TbsCertificateGenerator m_tbsGen;

        /// <summary>
        /// Creates an empty version 3 certificate generator.
        /// </summary>
        public X509V3CertificateGenerator()
        {
            m_tbsGen = new V3TbsCertificateGenerator();
        }

        /// <summary>
        /// Creates a generator for a version 3 certificate, initialised from another certificate.
        /// </summary>
        /// <param name="template">Template certificate to base the new one on.</param>
        public X509V3CertificateGenerator(X509Certificate template)
            : this(template.CertificateStructure)
        {
        }

        /// <summary>
        /// Creates a generator for a version 3 certificate, initialised from a parsed
        /// <see cref="X509CertificateStructure"/>.
        /// </summary>
        /// <param name="template">
        /// Template certificate structure to copy serial number, issuer, validity, subject, public key and
        /// extensions from (excluding alternate public key and alternate signature extensions).
        /// </param>
        public X509V3CertificateGenerator(X509CertificateStructure template)
        {
            m_tbsGen = new V3TbsCertificateGenerator();
            m_tbsGen.SetSerialNumber(template.SerialNumber);
            m_tbsGen.SetIssuer(template.Issuer);
            m_tbsGen.SetValidity(template.Validity);
            m_tbsGen.SetSubject(template.Subject);
            m_tbsGen.SetSubjectPublicKeyInfo(template.SubjectPublicKeyInfo);

            var extensions = template.Extensions;

            foreach (var oid in extensions.ExtensionOids)
            {
                if (X509Extensions.SubjectAltPublicKeyInfo.Equals(oid) ||
                    X509Extensions.AltSignatureAlgorithm.Equals(oid) ||
                    X509Extensions.AltSignatureValue.Equals(oid))
                {
                    continue;
                }

                var extension = extensions.GetExtension(oid);
                m_extGenerator.AddExtension(oid, extension.IsCritical, extension.Value.GetOctets());
            }
        }

        /// <summary>
        /// Reset the Generator.
        /// </summary>
        public void Reset()
        {
            m_tbsGen = new V3TbsCertificateGenerator();
            m_extGenerator.Reset();
        }

        /// <summary>
        /// Set the certificate's serial number.
        /// </summary>
        /// <remarks>
        /// Make serial numbers long; if you have no serial number policy make sure the number is at least
        /// 16 bytes of secure random data. You will be surprised how ugly a serial number collision can get.
        /// </remarks>
        /// <param name="serialNumber">The serial number.</param>
        /// <exception cref="ArgumentException">
        /// <paramref name="serialNumber"/> is not a positive integer.
        /// </exception>
        public void SetSerialNumber(BigInteger serialNumber)
        {
            if (serialNumber.SignValue <= 0)
                throw new ArgumentException("serial number must be a positive integer", nameof(serialNumber));

            m_tbsGen.SetSerialNumber(new DerInteger(serialNumber));
        }

        /// <summary>
        /// Set the distinguished name of the issuer.
        /// The issuer is the entity which is signing the certificate.
        /// </summary>
        /// <param name="issuer">The issuer's DN.</param>
        public void SetIssuerDN(X509Name issuer)
        {
            m_tbsGen.SetIssuer(issuer);
        }

        /// <summary>
        /// Sets the certificate validity period from a pre-built <see cref="Validity"/> structure.
        /// </summary>
        /// <param name="validity">The not-before and not-after times.</param>
        public void SetValidity(Validity validity)
        {
            m_tbsGen.SetValidity(validity);
        }

        /// <summary>
        /// Set the date that this certificate is to be valid from.
        /// </summary>
        /// <param name="date"/>
        public void SetNotBefore(DateTime date)
        {
            m_tbsGen.SetStartDate(new Time(date));
        }

        /// <summary>
        /// Set the date after which this certificate will no longer be valid.
        /// </summary>
        /// <param name="date"/>
        public void SetNotAfter(DateTime date)
        {
            m_tbsGen.SetEndDate(new Time(date));
        }

        /// <summary>
        /// Set the DN of the entity that this certificate is about.
        /// </summary>
        /// <param name="subject"/>
        public void SetSubjectDN(X509Name subject)
        {
            m_tbsGen.SetSubject(subject);
        }

        /// <summary>
        /// Set the public key that this certificate identifies.
        /// </summary>
        /// <param name="publicKey"/>
        public void SetPublicKey(AsymmetricKeyParameter publicKey)
        {
            m_tbsGen.SetSubjectPublicKeyInfo(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));
        }

        /// <summary>
        /// Set the SubjectPublicKeyInfo for the public key that this certificate identifies.
        /// </summary>
        /// <param name="subjectPublicKeyInfo"/>
        public void SetSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            m_tbsGen.SetSubjectPublicKeyInfo(subjectPublicKeyInfo);
        }

        /// <summary>
        /// Set the subject unique ID - note: it is very rare that it is correct to do this.
        /// </summary>
        /// <param name="uniqueID"/>
        public void SetSubjectUniqueID(bool[] uniqueID)
        {
            m_tbsGen.SetSubjectUniqueID(BooleanToBitString(uniqueID));
        }

        /// <summary>
        /// Set the issuer unique ID - note: it is very rare that it is correct to do this.
        /// </summary>
        /// <param name="uniqueID"/>
        public void SetIssuerUniqueID(bool[] uniqueID)
        {
            m_tbsGen.SetIssuerUniqueID(BooleanToBitString(uniqueID));
        }

        /// <summary>
        /// Add an extension using a string with a dotted decimal OID.
        /// </summary>
        /// <param name="oid">string containing a dotted decimal Object Identifier.</param>
        /// <param name="critical">Is it critical.</param>
        /// <param name="extensionValue">The value.</param>
        public void AddExtension(string oid, bool critical, Asn1Encodable extensionValue) =>
            AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);

        /// <summary>
        /// Add an extension to this certificate.
        /// </summary>
        /// <param name="oid">Its Object Identifier.</param>
        /// <param name="critical">Is it critical.</param>
        /// <param name="extensionValue">The value.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable extensionValue) =>
            m_extGenerator.AddExtension(oid, critical, extensionValue);

        /// <summary>
        /// Add an extension using a string with a dotted decimal OID.
        /// </summary>
        /// <param name="oid">string containing a dotted decimal Object Identifier.</param>
        /// <param name="critical">Is it critical.</param>
        /// <param name="extensionValue">The value.</param>
        public void AddExtension(string oid, bool critical, IAsn1Convertible extensionValue) =>
            AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);

        /// <summary>
        /// Add an extension to this certificate.
        /// </summary>
        /// <param name="oid">Its Object Identifier.</param>
        /// <param name="critical">Is it critical.</param>
        /// <param name="extensionValue">The value.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, IAsn1Convertible extensionValue) =>
            m_extGenerator.AddExtension(oid, critical, extensionValue);

        /// <summary>
        /// Add an extension using a string with a dotted decimal OID.
        /// </summary>
        /// <param name="oid">string containing a dotted decimal Object Identifier.</param>
        /// <param name="critical">Is it critical.</param>
        /// <param name="extensionValue">byte[] containing the value of this extension.</param>
        public void AddExtension(string oid, bool critical, byte[] extensionValue) =>
            AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);

        /// <summary>
        /// Add an extension to this certificate.
        /// </summary>
        /// <param name="oid">Its Object Identifier.</param>
        /// <param name="critical">Is it critical.</param>
        /// <param name="extensionValue">byte[] containing the value of this extension.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, byte[] extensionValue) =>
            m_extGenerator.AddExtension(oid, critical, DerOctetString.FromContents(extensionValue));

        /// <summary>
        /// Adds a pre-built extension value to this certificate.
        /// </summary>
        /// <param name="oid">The extension object identifier.</param>
        /// <param name="x509Extension">The extension, including criticality flag and value.</param>
        public void AddExtension(DerObjectIdentifier oid, X509Extension x509Extension) =>
            m_extGenerator.AddExtension(oid, x509Extension);

        /// <summary>
        /// Adds a parsed ASN.1 extension to this certificate.
        /// </summary>
        /// <param name="extension">The extension to add.</param>
        public void AddExtension(Asn1.X509.Extension extension) => m_extGenerator.AddExtension(extension);

        /// <summary>
        /// Adds all extensions from an <see cref="X509Extensions"/> collection.
        /// </summary>
        /// <param name="extensions">The extensions to copy into this certificate.</param>
        public void AddExtensions(X509Extensions extensions) => m_extGenerator.AddExtensions(extensions);

        /// <summary>
        /// Add a given extension field for the standard extensions tag (tag 3),
        /// copying the extension value from another certificate.
        /// </summary>
        [Obsolete("Use version taking a DerObjectIdentifier")]
        public void CopyAndAddExtension(string oid, bool critical, X509Certificate cert) =>
            CopyAndAddExtension(new DerObjectIdentifier(oid), critical, cert);

        /// <summary>
        /// Add a given extension field for the standard extensions tag (tag 3),
        /// copying the extension value from another certificate.
        /// </summary>
        /// <param name="oid">The extension object identifier.</param>
        /// <param name="critical"><c>true</c> if the copied extension should be marked critical.</param>
        /// <param name="cert">The certificate to copy the extension value from.</param>
        /// <exception cref="CertificateParsingException">
        /// <paramref name="cert"/> does not contain an extension with the given OID.
        /// </exception>
        public void CopyAndAddExtension(DerObjectIdentifier oid, bool critical, X509Certificate cert)
        {
            X509Extension ext = cert.GetExtension(oid) ??
                throw new CertificateParsingException("extension " + oid + " not present");

            try
            {
                m_extGenerator.AddExtension(oid, ext);
            }
            catch (Exception e)
            {
                throw new CertificateParsingException(e.Message, e);
            }
        }

        /// <summary>
        /// Generate a new <see cref="X509Certificate"/> using the provided <see cref="ISignatureFactory"/>.
        /// </summary>
        /// <param name="signatureFactory">A <see cref="ISignatureFactory">signature factory</see> with the necessary
        /// algorithm details.</param>
        /// <returns>An <see cref="X509Certificate"/>.</returns>
        public X509Certificate Generate(ISignatureFactory signatureFactory)
        {
            var sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

            m_tbsGen.SetSignature(sigAlgID);

            if (!m_extGenerator.IsEmpty)
            {
                var deltaExtension = m_extGenerator.GetExtension(X509Extensions.DRAFT_DeltaCertificateDescriptor);
                if (deltaExtension != null)
                {
                    var descriptor = DeltaCertificateTool.TrimDeltaCertificateDescriptor(
                        DeltaCertificateDescriptor.GetInstance(deltaExtension.GetParsedValue()),
                        m_tbsGen.GenerateTbsCertificate(),
                        m_extGenerator.Generate());

                    m_extGenerator.ReplaceExtension(X509Extensions.DRAFT_DeltaCertificateDescriptor,
                        deltaExtension.IsCritical, descriptor);
                }

                m_tbsGen.SetExtensions(m_extGenerator.Generate());
            }

            var tbsCertificate = m_tbsGen.GenerateTbsCertificate();
            var signature = X509Utilities.GenerateSignature(signatureFactory, tbsCertificate);
            return new X509Certificate(new X509CertificateStructure(tbsCertificate, sigAlgID, signature));
        }

        /// <summary>
        /// Generate a new <see cref="X509Certificate"/> using the provided <see cref="ISignatureFactory"/> and
        /// containing altSignatureAlgorithm and altSignatureValue extensions based on the passed
        /// <paramref name="altSignatureFactory"/>.
        /// </summary>
        /// <param name="signatureFactory">A <see cref="ISignatureFactory">signature factory</see> with the necessary
        /// algorithm details.</param>
        /// <param name="isCritical">Whether the 'alt' extensions should be marked critical.</param>
        /// <param name="altSignatureFactory">A <see cref="ISignatureFactory">signature factory</see> used to create the
        /// altSignatureAlgorithm and altSignatureValue extensions.</param>
        /// <returns>An <see cref="X509Certificate"/>.</returns>
        public X509Certificate Generate(ISignatureFactory signatureFactory, bool isCritical,
            ISignatureFactory altSignatureFactory)
        {
            var sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;
            var altSigAlgID = (AlgorithmIdentifier)altSignatureFactory.AlgorithmDetails;

            m_extGenerator.AddExtension(X509Extensions.AltSignatureAlgorithm, isCritical, altSigAlgID);

            var deltaExtension = m_extGenerator.GetExtension(X509Extensions.DRAFT_DeltaCertificateDescriptor);
            if (deltaExtension != null)
            {
                m_tbsGen.SetSignature(sigAlgID);

                // the altSignatureValue is not present yet, but it must be in the deltaCertificate and
                // it must be different (by definition!). We add a dummy one to trigger inclusion.
                var tmpExtGenerator = new X509ExtensionsGenerator();
                tmpExtGenerator.AddExtensions(m_extGenerator.Generate());
                tmpExtGenerator.AddExtension(X509Extensions.AltSignatureValue, false, DerNull.Instance);

                var descriptor = DeltaCertificateTool.TrimDeltaCertificateDescriptor(
                    DeltaCertificateDescriptor.GetInstance(deltaExtension.GetParsedValue()),
                    m_tbsGen.GenerateTbsCertificate(),
                    tmpExtGenerator.Generate());

                m_extGenerator.ReplaceExtension(X509Extensions.DRAFT_DeltaCertificateDescriptor,
                    deltaExtension.IsCritical, descriptor);
            }

            m_tbsGen.SetSignature(null);
            m_tbsGen.SetExtensions(m_extGenerator.Generate());

            var altSignature = X509Utilities.GenerateSignature(altSignatureFactory,
                m_tbsGen.GeneratePreTbsCertificate());
            m_extGenerator.AddExtension(X509Extensions.AltSignatureValue, isCritical, altSignature);

            m_tbsGen.SetSignature(sigAlgID);
            m_tbsGen.SetExtensions(m_extGenerator.Generate());

            var tbsCertificate = m_tbsGen.GenerateTbsCertificate();
            var signature = X509Utilities.GenerateSignature(signatureFactory, tbsCertificate);
            return new X509Certificate(new X509CertificateStructure(tbsCertificate, sigAlgID, signature));
        }

        /// <summary>
        /// Allows enumeration of the signature names supported by the generator.
        /// </summary>
        [Obsolete("Will be removed")]
        public IEnumerable<string> SignatureAlgNames => X509Utilities.GetAlgNames();

        internal static DerBitString BooleanToBitString(bool[] id)
        {
            int byteLength = (id.Length + 7) / 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = byteLength <= 512
                ? stackalloc byte[byteLength]
                : new byte[byteLength];
#else
            byte[] bytes = new byte[byteLength];
#endif

            for (int i = 0; i != id.Length; i++)
            {
                bytes[i >> 3] |= (byte)(id[i] ? (0x80 >> (i & 7)) : 0);
            }

            return new DerBitString(bytes, (8 - id.Length) & 7);
        }
    }
}
