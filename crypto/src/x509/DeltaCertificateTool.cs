using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.X509
{
    /// <summary>
    /// General tool for handling the extension described in:
    /// https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/
    /// </summary>
    public class DeltaCertificateTool
    {
        public static Asn1.X509.Extension CreateDeltaCertificateExtension(bool isCritical,
            X509CertificateStructure deltaCert)
        {
            var descriptor = new DeltaCertificateDescriptor(
                deltaCert.SerialNumber,
                signature: deltaCert.SignatureAlgorithm,
                deltaCert.Issuer,
                deltaCert.Validity,
                deltaCert.Subject,
                deltaCert.SubjectPublicKeyInfo,
                deltaCert.Extensions,
                signatureValue: deltaCert.Signature);

            var extnID = X509Extensions.DRAFT_DeltaCertificateDescriptor;
            var critical = DerBoolean.GetInstance(isCritical);
            var extnValue = DerOctetString.WithContents(descriptor.GetEncoded(Asn1Encodable.Der));

            return new Asn1.X509.Extension(extnID, critical, extnValue);
        }

        public static Asn1.X509.Extension CreateDeltaCertificateExtension(bool isCritical, X509Certificate deltaCert) =>
            CreateDeltaCertificateExtension(isCritical, deltaCert.CertificateStructure);

        public static X509CertificateStructure ExtractDeltaCertificate(TbsCertificateStructure baseTbsCert)
        {
            var baseExtensions = baseTbsCert.Extensions;

            var dcdExtension = baseExtensions.GetExtension(X509Extensions.DRAFT_DeltaCertificateDescriptor) ??
                throw new InvalidOperationException("no deltaCertificateDescriptor present");

            var descriptor = DeltaCertificateDescriptor.GetInstance(dcdExtension.GetParsedValue());

            var version = baseTbsCert.VersionNumber;
            var serialNumber = descriptor.SerialNumber;
            var signature = descriptor.Signature ?? baseTbsCert.Signature;
            var issuer = descriptor.Issuer ?? baseTbsCert.Issuer;
            var validity = descriptor.Validity ?? baseTbsCert.Validity;
            var subject = descriptor.Subject ?? baseTbsCert.Subject;
            var subjectPublicKeyInfo = descriptor.SubjectPublicKeyInfo;
            var extensions = ExtractDeltaExtensions(descriptor.Extensions, baseExtensions);

            // TODO Copy over the issuerUniqueID and/or subjectUniqueID (if the issuer/subject resp. are unmodified)?
            var tbsCertificate = new TbsCertificateStructure(version, serialNumber, signature, issuer, validity,
                subject, subjectPublicKeyInfo, issuerUniqueID: null, subjectUniqueID: null, extensions);

            return new X509CertificateStructure(tbsCertificate, signature, descriptor.SignatureValue);
        }

        public static X509Certificate ExtractDeltaCertificate(X509Certificate baseCert) =>
            new X509Certificate(ExtractDeltaCertificate(baseCert.TbsCertificate));

        public static DeltaCertificateDescriptor TrimDeltaCertificateDescriptor(DeltaCertificateDescriptor descriptor,
            TbsCertificateStructure tbsCertificate, X509Extensions tbsExtensions)
        {
            DerInteger serialNumber = descriptor.SerialNumber;

            AlgorithmIdentifier signature = descriptor.Signature;
            if (signature != null && signature.Equals(tbsCertificate.Signature))
            {
                signature = null;
            }

            X509Name issuer = descriptor.Issuer;
            if (issuer != null && issuer.Equals(tbsCertificate.Issuer))
            {
                issuer = null;
            }

            Validity validity = descriptor.Validity;
            if (validity != null && validity.Equals(tbsCertificate.Validity))
            {
                validity = null;
            }

            X509Name subject = descriptor.Subject;
            if (subject != null && subject.Equals(tbsCertificate.Subject))
            {
                subject = null;
            }

            SubjectPublicKeyInfo subjectPublicKeyInfo = descriptor.SubjectPublicKeyInfo;

            X509Extensions extensions = descriptor.Extensions;
            if (extensions != null)
            {
                /*
                 * draft-bonnell-lamps-chameleon-certs-05 4.1:
                 *
                 * [The extensions] field MUST NOT contain any extension:
                 * - which has the same criticality and DER-encoded value as encoded in the Base Certificate,
                 * - whose type does not appear in the Base Certificate, or
                 * - which is of the DCD extension type (recursive Delta Certificates are not permitted).
                 * 
                 * [...] The ordering of extensions in [the extensions] field MUST be relative to the ordering of the
                 * extensions as they are encoded in the Delta [recte Base] Certificate.
                 */

                X509ExtensionsGenerator generator = new X509ExtensionsGenerator();

                foreach (DerObjectIdentifier oid in tbsExtensions.ExtensionOids)
                {
                    if (X509Extensions.DRAFT_DeltaCertificateDescriptor.Equals(oid))
                        continue;

                    X509Extension deltaExtension = extensions.GetExtension(oid);
                    if (deltaExtension != null && !deltaExtension.Equals(tbsExtensions.GetExtension(oid)))
                    {
                        generator.AddExtension(oid, deltaExtension);
                    }
                }

                extensions = generator.IsEmpty ? null : generator.Generate();
            }

            DerBitString signatureValue = descriptor.SignatureValue;

            return new DeltaCertificateDescriptor(serialNumber, signature, issuer, validity, subject,
                subjectPublicKeyInfo, extensions, signatureValue);
        }

        private static X509Extensions ExtractDeltaExtensions(X509Extensions descriptorExtensions,
            X509Extensions baseExtensions)
        {
            X509ExtensionsGenerator extGen = new X509ExtensionsGenerator();

            foreach (var oid in baseExtensions.ExtensionOids)
            {
                if (!X509Extensions.DRAFT_DeltaCertificateDescriptor.Equals(oid))
                {
                    extGen.AddExtension(oid, baseExtensions.GetExtension(oid));
                }
            }

            if (descriptorExtensions != null)
            {
                foreach (var oid in descriptorExtensions.ExtensionOids)
                {
                    extGen.ReplaceExtension(oid, descriptorExtensions.GetExtension(oid));
                }
            }

            return extGen.IsEmpty ? null : extGen.Generate();
        }
    }
}
