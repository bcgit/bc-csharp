using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>Diffie-Hellman domain validation parameters.</summary>
    /// <remarks>
    /// <code>
    /// ValidationParams ::= SEQUENCE {
    ///     seed        BIT STRING,
    ///     pgenCounter INTEGER
    /// }
    /// </code>
    /// </remarks>
    public sealed class ValidationParams
        : Asn1Encodable
    {
        public static ValidationParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ValidationParams validationParams)
                return validationParams;
            return new ValidationParams(Asn1Sequence.GetInstance(obj));
        }

        public static ValidationParams GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ValidationParams(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ValidationParams GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is ValidationParams validationParams)
                return validationParams;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new ValidationParams(asn1Sequence);

            return null;
        }

        public static ValidationParams GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ValidationParams(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerBitString m_seed;
        private readonly DerInteger m_pgenCounter;

        private ValidationParams(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_seed = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);
            m_pgenCounter = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public ValidationParams(DerBitString seed, DerInteger pgenCounter)
        {
            m_seed = seed ?? throw new ArgumentNullException(nameof(seed));
            m_pgenCounter = pgenCounter ?? throw new ArgumentNullException(nameof(pgenCounter));
        }

        public DerInteger PgenCounter => m_pgenCounter;

        public DerBitString Seed => m_seed;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_seed, m_pgenCounter);
    }
}
