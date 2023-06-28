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
        internal DerTaggedObject         version = new DerTaggedObject(0, new DerInteger(2));
        internal DerInteger              serialNumber;
        internal AlgorithmIdentifier     signature;
        internal X509Name                issuer;
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

		public void SetStartDate(Asn1UtcTime startDate)
        {
            this.startDate = new Time(startDate);
        }

		public void SetStartDate(Time startDate)
        {
            this.startDate = startDate;
        }

		public void SetEndDate(Asn1UtcTime endDate)
        {
            this.endDate = new Time(endDate);
        }

		public void SetEndDate(Time endDate)
        {
            this.endDate = endDate;
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

            if ((serialNumber == null)
                || (issuer == null) || (startDate == null) || (endDate == null)
                || (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
            {
                throw new InvalidOperationException("not all mandatory fields set in V3 TBScertificate generator");
            }

            return GenerateTbsStructure();
        }

        public TbsCertificateStructure GenerateTbsCertificate()
        {
            if ((serialNumber == null) || (signature == null)
                || (issuer == null) || (startDate == null) || (endDate == null)
                || (subject == null && !altNamePresentAndCritical) || (subjectPublicKeyInfo == null))
            {
                throw new InvalidOperationException("not all mandatory fields set in V3 TBScertificate generator");
            }

            return TbsCertificateStructure.GetInstance(GenerateTbsStructure());
        }

        private Asn1Sequence GenerateTbsStructure()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(10);

            v.Add(version);
            v.Add(serialNumber);
            v.AddOptional(signature);
            v.Add(issuer);

            //
            // before and after dates
            //
            v.Add(new DerSequence(startDate, endDate));

            if (subject != null)
            {
                v.Add(subject);
            }
            else
            {
                v.Add(DerSequence.Empty);
            }

            v.Add(subjectPublicKeyInfo);
            v.AddOptionalTagged(false, 1, issuerUniqueID);
            v.AddOptionalTagged(false, 2, subjectUniqueID);
            v.AddOptionalTagged(true, 3, extensions);

            return new DerSequence(v);
        }
    }
}
