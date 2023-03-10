using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
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
            version = new DerInteger(ver);
            return this;
        }

        public virtual CertTemplateBuilder SetSerialNumber(DerInteger ser)
        {
            serialNumber = ser;
            return this;
        }

        public virtual CertTemplateBuilder SetSigningAlg(AlgorithmIdentifier aid)
        {
            signingAlg = aid;
            return this;
        }

        public virtual CertTemplateBuilder SetIssuer(X509Name name)
        {
            issuer = name;
            return this;
        }

        public virtual CertTemplateBuilder SetValidity(OptionalValidity v)
        {
            validity = v;
            return this;
        }

        public virtual CertTemplateBuilder SetSubject(X509Name name)
        {
            subject = name;
            return this;
        }

        public virtual CertTemplateBuilder SetPublicKey(SubjectPublicKeyInfo spki)
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
            Asn1EncodableVector v = new Asn1EncodableVector(10);
            v.AddOptionalTagged(false, 0, version);
            v.AddOptionalTagged(false, 1, serialNumber);
            v.AddOptionalTagged(false, 2, signingAlg);
            v.AddOptionalTagged(true, 3, issuer); // CHOICE
            v.AddOptionalTagged(false, 4, validity);
            v.AddOptionalTagged(true, 5, subject); // CHOICE
            v.AddOptionalTagged(false, 6, publicKey);
            v.AddOptionalTagged(false, 7, issuerUID);
            v.AddOptionalTagged(false, 8, subjectUID);
            v.AddOptionalTagged(false, 9, extensions);
            return CertTemplate.GetInstance(new DerSequence(v));
        }
    }
}
