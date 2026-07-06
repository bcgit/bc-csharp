using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.BC
{
    /// <remarks>
    /// <code>
    /// SignatureCheck ::= SEQUENCE {
    ///     signatureAlgorithm  AlgorithmIdentifier,
    ///     certificates        [0] EXPLICIT Certificates OPTIONAL,
    ///     signatureValue      BIT STRING
    ///  }
    ///
    /// Certificates ::= SEQUENCE OF Certificate
    /// </code>
    /// </remarks>
    public sealed class SignatureCheck
        : Asn1Encodable
    {
        public static SignatureCheck GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignatureCheck signatureCheck)
                return signatureCheck;
            return new SignatureCheck(Asn1Sequence.GetInstance(obj));
        }

        public static SignatureCheck GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignatureCheck(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SignatureCheck GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignatureCheck(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly Asn1Sequence m_certificates;
        private readonly DerBitString m_signatureValue;

        public SignatureCheck(AlgorithmIdentifier signatureAlgorithm,
            IEnumerable<X509CertificateStructure> certificates, DerBitString signatureValue)
        {
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_certificates = certificates == null ? null
                : DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(certificates));
            m_signatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
        }

        public SignatureCheck(AlgorithmIdentifier signatureAlgorithm,
            IReadOnlyCollection<X509CertificateStructure> certificates, DerBitString signatureValue)
        {
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_certificates = certificates == null ? null : DerSequence.FromCollection(certificates);
            m_signatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
        }

        private SignatureCheck(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_signatureAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_certificates = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetInstance);
            m_signatureValue = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Asn1Sequence Certificates => m_certificates;

        public X509CertificateStructure[] GetCertificates() =>
            m_certificates?.MapElements(X509CertificateStructure.GetInstance);

        public AlgorithmIdentifier SignatureAlgorithm() => m_signatureAlgorithm;

        public DerBitString SignatureValue => m_signatureValue;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_signatureAlgorithm);
            v.AddOptionalTagged(true, 0, m_certificates);
            v.Add(m_signatureValue);
            return new DerSequence(v);
        }
    }
}
