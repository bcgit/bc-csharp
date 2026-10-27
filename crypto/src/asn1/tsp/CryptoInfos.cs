using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of the CryptoInfos element defined in RFC 4998:
     * <p/>
     * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
     */
    public class CryptoInfos
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CryptoInfos"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CryptoInfos"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CryptoInfos"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CryptoInfos GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CryptoInfos cryptoInfos)
                return cryptoInfos;
            return new CryptoInfos(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CryptoInfos"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CryptoInfos"/>.</returns>
        public static CryptoInfos GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CryptoInfos(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CryptoInfos"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CryptoInfos"/>.</returns>
        public static CryptoInfos GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CryptoInfos(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_attributes;

        private CryptoInfos(Asn1Sequence attributes)
        {
            m_attributes = attributes;
        }

        /// <summary>Create a new <see cref="CryptoInfos"/>.</summary>
        /// <param name="attrs">The attrs.</param>
        public CryptoInfos(Asn1.Cms.Attribute[] attrs)
        {
            m_attributes = DerSequence.FromElements(attrs);
        }

        /// <summary>Return the attributes.</summary>
        public virtual Asn1.Cms.Attribute[] GetAttributes() => m_attributes.MapElements(Asn1.Cms.Attribute.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_attributes;
    }
}
