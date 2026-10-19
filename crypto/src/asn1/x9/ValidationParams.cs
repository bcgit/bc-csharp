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
        /// <summary>Return an <see cref="ValidationParams"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ValidationParams"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ValidationParams"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ValidationParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ValidationParams validationParams)
                return validationParams;
            return new ValidationParams(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ValidationParams"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ValidationParams"/>.</returns>
        public static ValidationParams GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ValidationParams(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ValidationParams"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="ValidationParams"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="ValidationParams"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ValidationParams"/>.</returns>
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

        /// <summary>Create a new <see cref="ValidationParams"/>.</summary>
        /// <param name="seed">The seed.</param>
        /// <param name="pgenCounter">The pgen counter.</param>
        public ValidationParams(DerBitString seed, DerInteger pgenCounter)
        {
            m_seed = seed ?? throw new ArgumentNullException(nameof(seed));
            m_pgenCounter = pgenCounter ?? throw new ArgumentNullException(nameof(pgenCounter));
        }

        /// <summary>Gets the pgen counter.</summary>
        public DerInteger PgenCounter => m_pgenCounter;

        /// <summary>Gets the seed.</summary>
        public DerBitString Seed => m_seed;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_seed, m_pgenCounter);
    }
}
