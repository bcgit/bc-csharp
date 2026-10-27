using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The OptionalValidity structure of RFC 4211.</summary>
    public class OptionalValidity
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OptionalValidity"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OptionalValidity"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OptionalValidity"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OptionalValidity GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OptionalValidity optionalValidity)
                return optionalValidity;
            return new OptionalValidity(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OptionalValidity"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OptionalValidity"/>.</returns>
        public static OptionalValidity GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OptionalValidity(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OptionalValidity"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="OptionalValidity"/>, or null if <paramref name="element"/> is null.</returns>
        public static OptionalValidity GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OptionalValidity optionalValidity)
                return optionalValidity;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new OptionalValidity(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="OptionalValidity"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OptionalValidity"/>.</returns>
        public static OptionalValidity GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OptionalValidity(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Time m_notBefore;
        private readonly Time m_notAfter;

        private OptionalValidity(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_notBefore = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Time.GetTagged); // CHOICE
            m_notAfter = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Time.GetTagged); // CHOICE

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (m_notBefore == null && m_notAfter == null)
                throw new ArgumentException("at least one of notBefore/notAfter MUST be present.");
        }

        /// <summary>Create a new <see cref="OptionalValidity"/>.</summary>
        /// <param name="notBefore">The not before.</param>
        /// <param name="notAfter">The not after.</param>
        public OptionalValidity(Time notBefore, Time notAfter)
        {
            if (notBefore == null && notAfter == null)
                throw new ArgumentException("at least one of notBefore/notAfter MUST be present.");

            m_notBefore = notBefore;
            m_notAfter = notAfter;
        }

        /// <summary>Gets the not before.</summary>
        public virtual Time NotBefore => m_notBefore;

        /// <summary>Gets the not after.</summary>
        public virtual Time NotAfter => m_notAfter;

        /// <remarks>
        /// <code>
        /// OptionalValidity ::= SEQUENCE {
        ///     notBefore   [0] Time OPTIONAL,
        ///     notAfter    [1] Time OPTIONAL } --at least one MUST be present
        ///
        /// Time ::= CHOICE { ... }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(true, 0, m_notBefore); // CHOICE
            v.AddOptionalTagged(true, 1, m_notAfter); // CHOICE
            return new DerSequence(v);
        }
    }
}
