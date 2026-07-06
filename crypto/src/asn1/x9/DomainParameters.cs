using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>X9.44 Diffie-Hellman domain parameters.</summary>
    /// <remarks>
    /// <code>
    /// DomainParameters ::= SEQUENCE {
    ///     p                   INTEGER,            --odd prime, p = jq + 1
    ///     g                   INTEGER,            --generator, g
    ///     q                   INTEGER,            --factor of p-1
    ///     j                   INTEGER OPTIONAL,   --subgroup factor, j &gt;= 2
    ///     validationParams    ValidationParams OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public sealed class DomainParameters
        : Asn1Encodable
    {
        public static DomainParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DomainParameters domainParameters)
                return domainParameters;
            return new DomainParameters(Asn1Sequence.GetInstance(obj));
        }

        public static DomainParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DomainParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static DomainParameters GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DomainParameters domainParameters)
                return domainParameters;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new DomainParameters(asn1Sequence);

            return null;
        }

        public static DomainParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DomainParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_p, m_g, m_q, m_j;
        private readonly ValidationParams m_validationParams;

        private DomainParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_p = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_g = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_q = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_j = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_validationParams = Asn1Utilities.ReadOptional(seq, ref pos, ValidationParams.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DomainParameters(DerInteger p, DerInteger g, DerInteger q, DerInteger j,
            ValidationParams validationParams)
        {
            m_p = p ?? throw new ArgumentNullException(nameof(p));
            m_g = g ?? throw new ArgumentNullException(nameof(g));
            m_q = q ?? throw new ArgumentNullException(nameof(q));
            m_j = j;
            m_validationParams = validationParams;
        }

        public DerInteger P => m_p;

        public DerInteger G => m_g;

        public DerInteger Q => m_q;

        public DerInteger J => m_j;

        public ValidationParams ValidationParams => m_validationParams;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_p, m_g, m_q);
            v.AddOptional(m_j, m_validationParams);
            return new DerSequence(v);
        }
    }
}
