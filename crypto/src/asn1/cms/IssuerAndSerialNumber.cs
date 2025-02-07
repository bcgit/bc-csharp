using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Cms
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

        public static IssuerAndSerialNumber GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IssuerAndSerialNumber(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static IssuerAndSerialNumber GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IssuerAndSerialNumber(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly X509Name m_issuer;
        private readonly DerInteger m_serialNumber;

        private IssuerAndSerialNumber(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuer = X509Name.GetInstance(seq[0]);
            m_serialNumber = DerInteger.GetInstance(seq[1]);
        }

        // TODO[api] 'name' => 'issuer'
        public IssuerAndSerialNumber(X509Name name, BigInteger serialNumber)
        {
            m_issuer = name ?? throw new ArgumentNullException(nameof(name));
            m_serialNumber = new DerInteger(serialNumber);
        }

        // TODO[api] 'name' => 'issuer'
        public IssuerAndSerialNumber(X509Name name, DerInteger serialNumber)
        {
            m_issuer = name ?? throw new ArgumentNullException(nameof(name));
            m_serialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        }

        public IssuerAndSerialNumber(X509CertificateStructure x509CertificateStructure)
        {
            m_issuer = x509CertificateStructure.Issuer;
            m_serialNumber = x509CertificateStructure.SerialNumber;
        }

        public X509Name Issuer => m_issuer;

        [Obsolete("Use 'Issuer' property instead")]
        public X509Name Name => m_issuer;

        public DerInteger SerialNumber => m_serialNumber;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_issuer, m_serialNumber);
    }
}
