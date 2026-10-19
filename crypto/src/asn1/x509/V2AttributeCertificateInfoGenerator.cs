using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * Generator for Version 2 AttributeCertificateInfo
     * <pre>
     * AttributeCertificateInfo ::= Sequence {
     *       version              AttCertVersion -- version is v2,
     *       holder               Holder,
     *       issuer               AttCertIssuer,
     *       signature            AlgorithmIdentifier,
     *       serialNumber         CertificateSerialNumber,
     *       attrCertValidityPeriod   AttCertValidityPeriod,
     *       attributes           Sequence OF Attr,
     *       issuerUniqueID       UniqueIdentifier OPTIONAL,
     *       extensions           Extensions OPTIONAL
     * }
     * </pre>
     *
     */
    public class V2AttributeCertificateInfoGenerator
    {
        internal DerInteger version;
        internal Holder holder;
        internal AttCertIssuer issuer;
        internal AlgorithmIdentifier signature;
        internal DerInteger serialNumber;
        internal Asn1EncodableVector attributes;
        internal DerBitString issuerUniqueID;
        internal X509Extensions extensions;

        // Note: validity period start/end dates stored directly
        //internal AttCertValidityPeriod attrCertValidityPeriod;
        internal Asn1GeneralizedTime startDate, endDate;

        /// <summary>Create a new <see cref="V2AttributeCertificateInfoGenerator"/>.</summary>
        public V2AttributeCertificateInfoGenerator()
        {
            this.version = DerInteger.One;
            attributes = new Asn1EncodableVector();
        }

        /// <summary>Set the holder.</summary>
        /// <param name="holder">The holder.</param>
        public void SetHolder(
            Holder holder)
        {
            this.holder = holder;
        }

        public void AddAttribute(
            string oid,
            Asn1Encodable value)
        {
            attributes.Add(new AttributeX509(new DerObjectIdentifier(oid), new DerSet(value)));
        }

        /**
         * @param attribute
         */
        public void AddAttribute(AttributeX509 attribute)
        {
            attributes.Add(attribute);
        }

        /// <summary>Set the serial number.</summary>
        /// <param name="serialNumber">The serial number.</param>
        public void SetSerialNumber(
            DerInteger serialNumber)
        {
            this.serialNumber = serialNumber;
        }

        /// <summary>Set the signature.</summary>
        /// <param name="signature">The signature.</param>
        public void SetSignature(
            AlgorithmIdentifier signature)
        {
            this.signature = signature;
        }

        /// <summary>Set the issuer.</summary>
        /// <param name="issuer">The issuer.</param>
        public void SetIssuer(
            AttCertIssuer issuer)
        {
            this.issuer = issuer;
        }

        /// <summary>Set the start date.</summary>
        /// <param name="startDate">The start date.</param>
        public void SetStartDate(
            Asn1GeneralizedTime startDate)
        {
            this.startDate = startDate;
        }

        /// <summary>Set the end date.</summary>
        /// <param name="endDate">The end date.</param>
        public void SetEndDate(
            Asn1GeneralizedTime endDate)
        {
            this.endDate = endDate;
        }

        /// <summary>Set the issuer unique ID.</summary>
        /// <param name="issuerUniqueID">The issuer unique ID.</param>
        public void SetIssuerUniqueID(
            DerBitString issuerUniqueID)
        {
            this.issuerUniqueID = issuerUniqueID;
        }

        /// <summary>Set the extensions.</summary>
        /// <param name="extensions">The extensions.</param>
        public void SetExtensions(
            X509Extensions extensions)
        {
            this.extensions = extensions;
        }

        public AttributeCertificateInfo GenerateAttributeCertificateInfo()
        {
            if ((serialNumber == null) || (signature == null)
                || (issuer == null) || (startDate == null) || (endDate == null)
                || (holder == null) || (attributes == null))
            {
                throw new InvalidOperationException("Not all mandatory fields set in V2 AttributeCertificateInfo generator");
            }
            if (AttributeCertificateInfo.IsEmptyIssuer(issuer))
                throw new InvalidOperationException("Issuer is empty");

            Asn1EncodableVector v = new Asn1EncodableVector(
                version, holder, issuer, signature, serialNumber);

            //
            // before and after dates => AttCertValidityPeriod
            //
            v.Add(new AttCertValidityPeriod(startDate, endDate));

            // Attributes
            v.Add(new DerSequence(attributes));
            v.AddOptional(issuerUniqueID, extensions);

            return AttributeCertificateInfo.GetInstance(new DerSequence(v));
        }
    }
}
