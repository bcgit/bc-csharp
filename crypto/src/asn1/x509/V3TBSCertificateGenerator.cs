using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * Generator for Version 3 TbsCertificateStructures.
     * <pre>
     * TbsCertificate ::= Sequence {
     *      version          [ 0 ]  Version DEFAULT v1(0),
     *      serialNumber            CertificateSerialNumber,
     *      signature               AlgorithmIdentifier,
     *      issuer                  Name,
     *      validity                Validity,
     *      subject                 Name,
     *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
     *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
     *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
     *      extensions        [ 3 ] Extensions OPTIONAL
     *      }
     * </pre>
     *
     */
    public class V3TbsCertificateGenerator
    {
        private static readonly DerTaggedObject Version = new DerTaggedObject(0, DerInteger.Two);

        internal DerInteger              serialNumber;
        internal AlgorithmIdentifier     signature;
        internal X509Name                issuer;
        internal Validity                validity;
        internal Time                    startDate, endDate;
        internal X509Name                subject;
        internal SubjectPublicKeyInfo    subjectPublicKeyInfo;
        internal X509Extensions          extensions;

        private bool altNamePresentAndCritical;
        private DerBitString issuerUniqueID;
        private DerBitString subjectUniqueID;

        /// <summary>Create a new <see cref="V3TbsCertificateGenerator"/>.</summary>
        public V3TbsCertificateGenerator()
        {
        }

        /// <summary>Set the serial number.</summary>
        /// <param name="serialNumber">The serial number.</param>
        public void SetSerialNumber(DerInteger serialNumber)
        {
            this.serialNumber = serialNumber;
        }

        /// <summary>Set the signature.</summary>
        /// <param name="signature">The signature.</param>
        public void SetSignature(AlgorithmIdentifier signature)
        {
            this.signature = signature;
        }

        /// <summary>Set the issuer.</summary>
        /// <param name="issuer">The issuer.</param>
        public void SetIssuer(X509Name issuer)
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
        public void SetSubject(X509Name subject)
        {
            this.subject = subject;
        }

        /// <summary>Set the issuer unique ID.</summary>
        /// <param name="uniqueID">The unique ID.</param>
        public void SetIssuerUniqueID(DerBitString uniqueID)
        {
            this.issuerUniqueID = uniqueID;
        }

        /// <summary>Set the subject unique ID.</summary>
        /// <param name="uniqueID">The unique ID.</param>
        public void SetSubjectUniqueID(DerBitString uniqueID)
        {
            this.subjectUniqueID = uniqueID;
        }

        /// <summary>Set the subject public key info.</summary>
        /// <param name="pubKeyInfo">The pub key info.</param>
        public void SetSubjectPublicKeyInfo(SubjectPublicKeyInfo pubKeyInfo)
        {
            this.subjectPublicKeyInfo = pubKeyInfo;
        }

        /// <summary>Set the extensions.</summary>
        /// <param name="extensions">The extensions.</param>
        public void SetExtensions(X509Extensions extensions)
        {
            this.extensions = extensions;

            if (extensions != null)
            {
                X509Extension altName = extensions.GetExtension(X509Extensions.SubjectAlternativeName);

                if (altName != null && altName.IsCritical)
                {
                    altNamePresentAndCritical = true;
                }
            }
        }

        /// <summary>
        /// Generate the TBSCertificate without the signature algorithm, as used when the signature is calculated before
        /// the algorithm is known.
        /// </summary>
        /// <returns>The pre-TBSCertificate sequence.</returns>
        public Asn1Sequence GeneratePreTbsCertificate()
        {
            if (signature != null)
                throw new InvalidOperationException("Signature field should not be set in PreTBSCertificate");

            if ((serialNumber == null) || (issuer == null) ||
                (validity == null && (startDate == null || endDate == null)) ||
                (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
            {
                throw new InvalidOperationException("Not all mandatory fields set in V3 TBScertificate generator");
            }

            if (issuer.IsEmpty)
                throw new InvalidOperationException("Issuer is an empty distinguished name");

            Asn1EncodableVector v = new Asn1EncodableVector(9);
            v.Add(Version);
            v.Add(serialNumber);
            // No signature
            v.Add(issuer);
            v.Add(validity ?? new Validity(startDate, endDate));
            v.Add(subject ?? X509Name.GetInstance(DerSequence.Empty));
            v.Add(subjectPublicKeyInfo);
            v.AddOptionalTagged(false, 1, issuerUniqueID);
            v.AddOptionalTagged(false, 2, subjectUniqueID);
            v.AddOptionalTagged(true, 3, extensions);
            return new DerSequence(v);
        }

        /// <summary>Generate the TBSCertificate from the state of the generator.</summary>
        /// <returns>The TBSCertificate.</returns>
        /// <exception cref="InvalidOperationException">A required field has not been set.</exception>
        public TbsCertificateStructure GenerateTbsCertificate()
        {
            if ((serialNumber == null) || (signature == null) || (issuer == null) ||
                (validity == null && (startDate == null || endDate == null)) ||
                (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
            {
                throw new InvalidOperationException("Not all mandatory fields set in V3 TBScertificate generator");
            }

            if (issuer.IsEmpty)
                throw new InvalidOperationException("Issuer is an empty distinguished name");

            return new TbsCertificateStructure(version: DerInteger.Two, serialNumber, signature, issuer,
                validity ?? new Validity(startDate, endDate), subject ?? X509Name.GetInstance(DerSequence.Empty),
                subjectPublicKeyInfo, issuerUniqueID, subjectUniqueID, extensions);
        }
    }
}
