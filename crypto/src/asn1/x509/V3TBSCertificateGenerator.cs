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

		public V3TbsCertificateGenerator()
        {
        }

		public void SetSerialNumber(DerInteger serialNumber)
        {
            this.serialNumber = serialNumber;
        }

		public void SetSignature(AlgorithmIdentifier signature)
        {
            this.signature = signature;
        }

		public void SetIssuer(X509Name issuer)
        {
            this.issuer = issuer;
        }

        public void SetValidity(Validity validity)
        {
            this.validity = validity;
            this.startDate = null;
            this.endDate = null;
        }

        public void SetStartDate(Time startDate)
        {
            this.validity = null;
            this.startDate = startDate;
        }

        public void SetStartDate(Asn1UtcTime startDate)
        {
            SetStartDate(new Time(startDate));
        }

        public void SetEndDate(Time endDate)
        {
            this.validity = null;
            this.endDate = endDate;
        }

        public void SetEndDate(Asn1UtcTime endDate)
        {
            SetEndDate(new Time(endDate));
        }

        public void SetSubject(X509Name subject)
        {
            this.subject = subject;
        }

		public void SetIssuerUniqueID(DerBitString uniqueID)
		{
			this.issuerUniqueID = uniqueID;
		}

		public void SetSubjectUniqueID(DerBitString uniqueID)
		{
			this.subjectUniqueID = uniqueID;
		}

		public void SetSubjectPublicKeyInfo(SubjectPublicKeyInfo pubKeyInfo)
        {
            this.subjectPublicKeyInfo = pubKeyInfo;
        }

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

        public Asn1Sequence GeneratePreTbsCertificate()
        {
            if (signature != null)
                throw new InvalidOperationException("signature field should not be set in PreTBSCertificate");

            if ((serialNumber == null) || (issuer == null) ||
                (validity == null && (startDate == null || endDate == null)) ||
                (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
            {
                throw new InvalidOperationException("not all mandatory fields set in V3 TBScertificate generator");
            }

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

        public TbsCertificateStructure GenerateTbsCertificate()
        {
            if ((serialNumber == null) || (signature == null) || (issuer == null) ||
                (validity == null && (startDate == null || endDate == null)) ||
                (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
            {
                throw new InvalidOperationException("not all mandatory fields set in V3 TBScertificate generator");
            }

            return new TbsCertificateStructure(version: DerInteger.Two, serialNumber, signature, issuer,
                validity ?? new Validity(startDate, endDate), subject ?? X509Name.GetInstance(DerSequence.Empty),
                subjectPublicKeyInfo, issuerUniqueID, subjectUniqueID, extensions);
        }
    }
}
