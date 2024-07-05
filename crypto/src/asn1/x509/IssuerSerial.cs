using System;

namespace Org.BouncyCastle.Asn1.X509
{
    public class IssuerSerial
        : Asn1Encodable
    {
		public static IssuerSerial GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is IssuerSerial issuerSerial)
                return issuerSerial;
            return new IssuerSerial(Asn1Sequence.GetInstance(obj));
		}

        public static IssuerSerial GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new IssuerSerial(Asn1Sequence.GetInstance(obj, explicitly));

        public static IssuerSerial GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is IssuerSerial issuerSerial)
                return issuerSerial;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new IssuerSerial(asn1Sequence);

            return null;
        }

        public static IssuerSerial GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IssuerSerial(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralNames m_issuer;
        private readonly DerInteger m_serial;
        private readonly DerBitString m_issuerUid;

        private IssuerSerial(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuer = GeneralNames.GetInstance(seq[pos++]);
            m_serial = DerInteger.GetInstance(seq[pos++]);
            m_issuerUid = Asn1Utilities.ReadOptional(seq, ref pos, DerBitString.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public IssuerSerial(GeneralNames issuer, DerInteger serial)
            : this(issuer, serial, null)
        {
        }

        public IssuerSerial(GeneralNames issuer, DerInteger serial, DerBitString issuerUid)
        {
            m_issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            m_serial = serial ?? throw new ArgumentNullException(nameof(serial));
            m_issuerUid = issuerUid;
        }

        public GeneralNames Issuer => m_issuer;

        public DerInteger Serial => m_serial;

        public DerBitString IssuerUid => m_issuerUid;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  IssuerSerial  ::=  Sequence {
         *       issuer         GeneralNames,
         *       serial         CertificateSerialNumber,
         *       issuerUid      UniqueIdentifier OPTIONAL
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_issuerUid == null
                ?  new DerSequence(m_issuer, m_serial)
                :  new DerSequence(m_issuer, m_serial, m_issuerUid);
        }
	}
}
