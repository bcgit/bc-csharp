using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * Generator for Version 1 TbsCertificateStructures.
     * <pre>
     * TbsCertificate ::= Sequence {
     *      version          [ 0 ]  Version DEFAULT v1(0),
     *      serialNumber            CertificateSerialNumber,
     *      signature               AlgorithmIdentifier,
     *      issuer                  Name,
     *      validity                Validity,
     *      subject                 Name,
     *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
     *      }
     * </pre>
     *
     */
    public class V1TbsCertificateGenerator
    {
        internal DerTaggedObject version = new DerTaggedObject(0, DerInteger.Zero);
        internal DerInteger serialNumber;
        internal AlgorithmIdentifier signature;
        internal X509Name issuer;
        internal Validity               validity;
        internal Time startDate, endDate;
        internal X509Name subject;
        internal SubjectPublicKeyInfo subjectPublicKeyInfo;

        /// <summary>Create a new <see cref="V1TbsCertificateGenerator"/>.</summary>
        public V1TbsCertificateGenerator()
        {
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
            X509Name issuer)
        {
            this.issuer = issuer;
        }

        /// <summary>Set the validity.</summary>
        /// <param name="validity">The validity.</param>
        public void SetValidity(Validity validity)
        {
            this.validity = validity;
            this.startDate = null;
            this.endDate = null;
        }

        /// <summary>Set the start date.</summary>
        /// <param name="startDate">The start date.</param>
        public void SetStartDate(Time startDate)
        {
            this.validity = null;
            this.startDate = startDate;
        }

        /// <summary>Set the start date.</summary>
        /// <param name="startDate">The start date.</param>
        public void SetStartDate(Asn1UtcTime startDate)
        {
            SetStartDate(new Time(startDate));
        }

        /// <summary>Set the end date.</summary>
        /// <param name="endDate">The end date.</param>
        public void SetEndDate(Time endDate)
        {
            this.validity = null;
            this.endDate = endDate;
        }

        /// <summary>Set the end date.</summary>
        /// <param name="endDate">The end date.</param>
        public void SetEndDate(Asn1UtcTime endDate)
        {
            SetEndDate(new Time(endDate));
        }

        /// <summary>Set the subject.</summary>
        /// <param name="subject">The subject.</param>
        public void SetSubject(
            X509Name subject)
        {
            this.subject = subject;
        }

        /// <summary>Set the subject public key info.</summary>
        /// <param name="pubKeyInfo">The pub key info.</param>
        public void SetSubjectPublicKeyInfo(
            SubjectPublicKeyInfo pubKeyInfo)
        {
            this.subjectPublicKeyInfo = pubKeyInfo;
        }

        /// <summary>Generate the TBSCertificate from the state of the generator.</summary>
        /// <returns>The TBSCertificate.</returns>
        /// <exception cref="InvalidOperationException">A required field has not been set.</exception>
        public TbsCertificateStructure GenerateTbsCertificate()
        {
            if ((serialNumber == null) || (signature == null) || (issuer == null) ||
                (validity == null && (startDate == null || endDate == null)) ||
                (subject == null) || (subjectPublicKeyInfo == null))
            {
                throw new InvalidOperationException("Not all mandatory fields set in V1 TBScertificate generator");
            }

            if (issuer.IsEmpty)
                throw new InvalidOperationException("Issuer is an empty distinguished name");

            return new TbsCertificateStructure(version: DerInteger.Zero, serialNumber, signature, issuer,
                validity ?? new Validity(startDate, endDate), subject, subjectPublicKeyInfo,
                issuerUniqueID: null, subjectUniqueID: null, extensions: null);
        }
    }
}
