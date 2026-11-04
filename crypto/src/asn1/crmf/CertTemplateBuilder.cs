using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>Builder for <see cref="CertTemplate"/> instances.</summary>
    public class CertTemplateBuilder
    {
        private DerInteger version;
        private DerInteger serialNumber;
        private AlgorithmIdentifier signingAlg;
        private X509Name issuer;
        private OptionalValidity validity;
        private X509Name subject;
        private SubjectPublicKeyInfo publicKey;
        private DerBitString issuerUID;
        private DerBitString subjectUID;
        private X509Extensions extensions;

        /** Sets the X.509 version. Note: for X509v3, use 2 here. */
        public virtual CertTemplateBuilder SetVersion(int ver)
        {
            version = DerInteger.ValueOf(ver);
            return this;
        }

        /// <summary>Set the serial number.</summary>
        /// <param name="ser">The serial number.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetSerialNumber(DerInteger ser)
        {
            serialNumber = ser;
            return this;
        }

        /// <summary>Set the signing algorithm.</summary>
        /// <param name="aid">The signing algorithm identifier.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetSigningAlg(AlgorithmIdentifier aid)
        {
            signingAlg = aid;
            return this;
        }

        /// <summary>Set the issuer.</summary>
        /// <param name="name">The issuer name.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetIssuer(X509Name name)
        {
            issuer = name;
            return this;
        }

        /// <summary>Set the validity.</summary>
        /// <param name="v">The validity.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetValidity(OptionalValidity v)
        {
            validity = v;
            return this;
        }

        /// <summary>Set the validity from optional start and end times.</summary>
        /// <param name="notBefore">The start of the validity period, or null.</param>
        /// <param name="notAfter">The end of the validity period, or null.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetValidity(DateTime? notBefore, DateTime? notAfter) =>
            SetValidity(new OptionalValidity(CreateTime(notBefore), CreateTime(notAfter)));

        /// <summary>Set the subject.</summary>
        /// <param name="name">The subject name.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetSubject(X509Name name)
        {
            subject = name;
            return this;
        }

        /// <summary>Set the subject public key info.</summary>
        /// <param name="spki">The subject public key info.</param>
        /// <returns>This builder.</returns>
        [Obsolete("Use 'SetSubjectPublicKeyInfo' instead")]
        public virtual CertTemplateBuilder SetPublicKey(SubjectPublicKeyInfo spki) => SetSubjectPublicKeyInfo(spki);

        /// <summary>Set the subject public key info.</summary>
        /// <param name="spki">The subject public key info.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetSubjectPublicKeyInfo(SubjectPublicKeyInfo spki)
        {
            publicKey = spki;
            return this;
        }

        /** Sets the issuer unique ID (deprecated in X.509v3) */
        public virtual CertTemplateBuilder SetIssuerUID(DerBitString uid)
        {
            issuerUID = uid;
            return this;
        }

        /** Sets the subject unique ID (deprecated in X.509v3) */
        public virtual CertTemplateBuilder SetSubjectUID(DerBitString uid)
        {
            subjectUID = uid;
            return this;
        }

        /// <summary>Set the extensions.</summary>
        /// <param name="extens">The extensions.</param>
        /// <returns>This builder.</returns>
        public virtual CertTemplateBuilder SetExtensions(X509Extensions extens)
        {
            extensions = extens;
            return this;
        }

        /**
         * <pre>
         *  CertTemplate ::= SEQUENCE {
         *      version      [0] Version               OPTIONAL,
         *      serialNumber [1] INTEGER               OPTIONAL,
         *      signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
         *      issuer       [3] Name                  OPTIONAL,
         *      validity     [4] OptionalValidity      OPTIONAL,
         *      subject      [5] Name                  OPTIONAL,
         *      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
         *      issuerUID    [7] UniqueIdentifier      OPTIONAL,
         *      subjectUID   [8] UniqueIdentifier      OPTIONAL,
         *      extensions   [9] Extensions            OPTIONAL }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public virtual CertTemplate Build()
        {
            return new CertTemplate(version, serialNumber, signingAlg, issuer, validity, subject, publicKey,
                issuerUID, subjectUID, extensions);
        }

        private static Time CreateTime(DateTime? dateTime) => dateTime == null ? null : new Time(dateTime.Value);
    }
}
