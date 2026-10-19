using System;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of PartialHashtree, as defined in RFC 4998.
     * <p/>
     * The ASN.1 notation for a PartialHashTree is:
     * <p/>
     * PartialHashtree ::= SEQUENCE OF OCTET STRING
     */
    public class PartialHashtree
        : Asn1Encodable
    {
        /**
         * Return a PartialHashtree from the given object.
         *
         * @param obj the object we want converted.
         * @return a PartialHashtree instance, or null.
         * @throws IllegalArgumentException if the object cannot be converted.
         */
        public static PartialHashtree GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PartialHashtree partialHashtree)
                return partialHashtree;
            return new PartialHashtree(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PartialHashtree"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PartialHashtree"/>.</returns>
        public static PartialHashtree GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PartialHashtree(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PartialHashtree"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PartialHashtree"/>.</returns>
        public static PartialHashtree GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PartialHashtree(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        /**
         * Hash values that constitute the hash tree, as ASN.1 Octet Strings.
         */
        private readonly Asn1Sequence m_values;

        private PartialHashtree(Asn1Sequence values)
        {
            for (int i = 0; i != values.Count; i++)
            {
                if (!(values[i] is Asn1OctetString))
                    throw new ArgumentException("unknown object in constructor: " + Platform.GetTypeName(values[i]));
            }
            m_values = values;
        }

        /// <summary>Create a new <see cref="PartialHashtree"/>.</summary>
        /// <param name="values">The values.</param>
        public PartialHashtree(params byte[][] values)
        {
            m_values = DerSequence.Map(values, DerOctetString.FromContents);
        }

        /// <summary>Gets the value count.</summary>
        public virtual int ValueCount => m_values.Count;

        /// <summary>Return the values.</summary>
        public virtual byte[][] GetValues() => m_values.MapElements(
            element => Arrays.Clone(Asn1OctetString.GetInstance(element).GetOctets()));

        public virtual bool ContainsHash(byte[] hash)
        {
            foreach (Asn1OctetString octetString in m_values)
            {
                byte[] currentHash = octetString.GetOctets();

                if (Arrays.FixedTimeEquals(hash, currentHash))
                    return true;
            }

            return false;
        }

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_values;
    }
}
