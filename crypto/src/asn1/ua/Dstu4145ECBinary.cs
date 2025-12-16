using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.Field;

namespace Org.BouncyCastle.Asn1.UA
{
    public class Dstu4145ECBinary
        : Asn1Encodable
    {
        private static DerInteger DefaultVersion = DerInteger.Zero;

        public static Dstu4145ECBinary GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Dstu4145ECBinary dstu4145ECBinary)
                return dstu4145ECBinary;
            return new Dstu4145ECBinary(Asn1Sequence.GetInstance(obj));
        }

        public static Dstu4145ECBinary GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145ECBinary(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Dstu4145ECBinary GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Dstu4145ECBinary dstu4145ECBinary)
                return dstu4145ECBinary;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Dstu4145ECBinary(asn1Sequence);

            return null;
        }

        public static Dstu4145ECBinary GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145ECBinary(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Dstu4145BinaryField m_f;
        private readonly DerInteger m_a;
        private readonly Asn1OctetString m_b;
        private readonly DerInteger m_n;
        private readonly Asn1OctetString m_bp;

        public Dstu4145ECBinary(ECDomainParameters domainParameters)
        {
            ECCurve curve = domainParameters.Curve;
            if (!ECAlgorithms.IsF2mCurve(curve))
                throw new ArgumentException("only binary domain is possible", nameof(domainParameters));

            // We always use big-endian in parameter encoding

            IPolynomialExtensionField field = (IPolynomialExtensionField)curve.Field;
            int[] exponents = field.MinimalPolynomial.GetExponentsPresent();
            if (exponents.Length == 3)
            {
                m_f = new Dstu4145BinaryField(exponents[2], exponents[1]);
            }
            else if (exponents.Length == 5)
            {
                m_f = new Dstu4145BinaryField(exponents[4], exponents[1], exponents[2], exponents[3]);
            }
            else
            {
                throw new ArgumentException("curve must have a trinomial or pentanomial basis", nameof(domainParameters));
            }

            m_a = new DerInteger(curve.A.ToBigInteger());
            m_b = new DerOctetString(curve.B.GetEncoded());
            m_n = new DerInteger(domainParameters.N);
            m_bp = new DerOctetString(Dstu4145PointEncoder.EncodePoint(domainParameters.G));
        }

        private Dstu4145ECBinary(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 5 || count > 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerInteger.GetTagged)
                ?? DefaultVersion;

            m_f = Dstu4145BinaryField.GetInstance(seq[pos++]);
            m_a = DerInteger.GetInstance(seq[pos++]);
            m_b = Asn1OctetString.GetInstance(seq[pos++]);
            m_n = DerInteger.GetInstance(seq[pos++]);
            m_bp = Asn1OctetString.GetInstance(seq[pos++]);
        }

        public Dstu4145BinaryField Field => m_f;

        public DerInteger A => m_a;

        public Asn1OctetString B => m_b;

        public DerInteger N => m_n;

        public Asn1OctetString BP => m_bp;

        /**
         * ECBinary  ::= SEQUENCE {
         * version          [0] EXPLICIT INTEGER    DEFAULT 0,
         * f     BinaryField,
         * a    INTEGER (0..1),
         * b    OCTET STRING,
         * n    INTEGER,
         * bp    OCTET STRING}
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(6);

            if (!DefaultVersion.Equals(m_version))
            {
                v.Add(new DerTaggedObject(true, 0, m_version));
            }

            v.Add(m_f);
            v.Add(m_a);
            v.Add(m_b);
            v.Add(m_n);
            v.Add(m_bp);

            return new DerSequence(v);
        }
    }
}
