using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class IssuerAndSerialNumber
        : Asn1Encodable
    {
		public static IssuerAndSerialNumber GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is IssuerAndSerialNumber issuerAndSerialNumber)
                return issuerAndSerialNumber;
            return new IssuerAndSerialNumber(Asn1Sequence.GetInstance(obj));
		}

        public static IssuerAndSerialNumber GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new IssuerAndSerialNumber(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly X509Name m_name;
        private readonly DerInteger m_certSerialNumber;

        private IssuerAndSerialNumber(Asn1Sequence seq)
        {
            int count = seq.Count;
			if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_name = X509Name.GetInstance(seq[0]);
            m_certSerialNumber = DerInteger.GetInstance(seq[1]);
        }

        public IssuerAndSerialNumber(X509Name name, BigInteger certSerialNumber)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_certSerialNumber = new DerInteger(certSerialNumber);
        }

        public IssuerAndSerialNumber(X509Name name, DerInteger certSerialNumber)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_certSerialNumber = certSerialNumber ?? throw new ArgumentNullException(nameof(certSerialNumber));
        }

        public X509Name Name => m_name;

        public DerInteger CertificateSerialNumber => m_certSerialNumber;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_name, m_certSerialNumber);
    }
}
