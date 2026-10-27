using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>
    /// The Controls structure of RFC 4211: a sequence of attributes controlling the issuing of the certificate.
    /// </summary>
    public class Controls
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Controls"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Controls"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Controls"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Controls GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Controls controls)
                return controls;
            return new Controls(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Controls"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Controls"/>.</returns>
        public static Controls GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Controls(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Controls"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Controls"/>, or null if <paramref name="element"/> is null.</returns>
        public static Controls GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Controls controls)
                return controls;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Controls(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="Controls"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Controls"/>.</returns>
        public static Controls GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Controls(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private Controls(Asn1Sequence seq)
        {
            m_content = seq;
        }

        /// <summary>Create a new <see cref="Controls"/>.</summary>
        /// <param name="atvs">The atvs.</param>
        public Controls(params AttributeTypeAndValue[] atvs)
        {
            m_content = new DerSequence(atvs);
        }

        /// <summary>Return the controls as an array.</summary>
        /// <returns>A new array holding the controls.</returns>
        public virtual AttributeTypeAndValue[] ToAttributeTypeAndValueArray() =>
            m_content.MapElements(AttributeTypeAndValue.GetInstance);

        /**
         * <pre>
         * Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
