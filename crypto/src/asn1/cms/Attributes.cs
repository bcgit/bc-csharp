using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The Attributes structure of RFC 5652: a set of attributes.</summary>
    public class Attributes
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Attributes"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Attributes"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Attributes"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Attributes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Attributes attributes)
                return attributes;
            return new Attributes(Asn1Set.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Attributes"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Attributes"/>.</returns>
        public static Attributes GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Attributes(Asn1Set.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Attributes"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Attributes"/>, or null if <paramref name="element"/> is null.</returns>
        public static Attributes GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Attributes attributes)
                return attributes;

            Asn1Set asn1Set = Asn1Set.GetOptional(element);
            if (asn1Set != null)
                return new Attributes(asn1Set);

            return null;
        }

        /// <summary>Return an <see cref="Attributes"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Attributes"/>.</returns>
        public static Attributes GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Attributes(Asn1Set.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Set m_attributes;

        private Attributes(Asn1Set attributes)
        {
            m_attributes = attributes;
        }

        /// <summary>Create a new <see cref="Attributes"/>.</summary>
        /// <param name="v">The v.</param>
        public Attributes(Asn1EncodableVector v)
        {
            m_attributes = BerSet.FromVector(v);
        }

        /// <summary>Create a new <see cref="Attributes"/>.</summary>
        /// <param name="attributes">The attributes.</param>
        public Attributes(IReadOnlyCollection<Attribute> attributes)
        {
            m_attributes = BerSet.FromCollection(attributes);
        }

        /// <summary>Gets the attribute set.</summary>
        public Asn1Set AttributeSet => m_attributes;

        /// <summary>Return the attributes.</summary>
        public virtual Attribute[] GetAttributes() => m_attributes.MapElements(Attribute.GetInstance);

        /// <remarks>
        /// <code>
        /// Attributes ::= SET SIZE(1..MAX) OF Attribute --according to RFC 5652
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object() => m_attributes;
    }
}
