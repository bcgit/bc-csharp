using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.Field;

namespace Org.BouncyCastle.Asn1.UA
{
    /// <summary>The elliptic curve parameters over a binary field of DSTU 4145-2002.</summary>
    public class Dstu4145ECBinary
        : Asn1Encodable
    {
        private static DerInteger DefaultVersion = DerInteger.Zero;

        /// <summary>Return an <see cref="Dstu4145ECBinary"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Dstu4145ECBinary"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Dstu4145ECBinary"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Dstu4145ECBinary GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Dstu4145ECBinary dstu4145ECBinary)
                return dstu4145ECBinary;
            return new Dstu4145ECBinary(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Dstu4145ECBinary"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Dstu4145ECBinary"/>.</returns>
        public static Dstu4145ECBinary GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145ECBinary(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Dstu4145ECBinary"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Dstu4145ECBinary"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="Dstu4145ECBinary"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Dstu4145ECBinary"/>.</returns>
        public static Dstu4145ECBinary GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Dstu4145ECBinary(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Dstu4145BinaryField m_f;
        private readonly DerInteger m_a;
        private readonly Asn1OctetString m_b;
        private readonly DerInteger m_n;
        private readonly Asn1OctetString m_bp;

        /// <summary>Create a new <see cref="Dstu4145ECBinary"/>.</summary>
        /// <param name="domainParameters">The domain parameters.</param>
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

            m_f = Asn1Utilities.Read(seq, ref pos, Dstu4145BinaryField.GetInstance);
            m_a = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_b = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_n = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_bp = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
        }

        public Dstu4145BinaryField Field => m_f;

        /// <summary>Gets the a.</summary>
        public DerInteger A => m_a;

        /// <summary>Gets the b.</summary>
        public Asn1OctetString B => m_b;

        /// <summary>Gets the n.</summary>
        public DerInteger N => m_n;

        /// <summary>Gets the BP.</summary>
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
