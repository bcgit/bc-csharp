using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <summary>
    /// Summary description for OtherHashAlgAndValue.
    /// </summary>
    /// <remarks>
    /// <code>
    /// OtherHashAlgAndValue ::= SEQUENCE {
    /// hashAlgorithm AlgorithmIdentifier,
    /// 	hashValue OtherHashValue
    /// }
    ///
    /// OtherHashValue ::= OCTET STRING
    /// </code>
    /// </remarks>
    public class OtherHashAlgAndValue
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OtherHashAlgAndValue"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OtherHashAlgAndValue"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OtherHashAlgAndValue"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OtherHashAlgAndValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherHashAlgAndValue otherHashAlgAndValue)
                return otherHashAlgAndValue;
            return new OtherHashAlgAndValue(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OtherHashAlgAndValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherHashAlgAndValue"/>.</returns>
        public static OtherHashAlgAndValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherHashAlgAndValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OtherHashAlgAndValue"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="OtherHashAlgAndValue"/>, or null if <paramref name="element"/> is null.</returns>
        public static OtherHashAlgAndValue GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OtherHashAlgAndValue otherHashAlgAndValue)
                return otherHashAlgAndValue;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new OtherHashAlgAndValue(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="OtherHashAlgAndValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherHashAlgAndValue"/>.</returns>
        public static OtherHashAlgAndValue GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherHashAlgAndValue(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly Asn1OctetString m_hashValue;

        private OtherHashAlgAndValue(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_hashValue = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OtherHashAlgAndValue"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="hashValue">The hash value.</param>
        public OtherHashAlgAndValue(AlgorithmIdentifier hashAlgorithm, byte[] hashValue)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_hashValue = DerOctetString.FromContents(hashValue);
        }

        /// <summary>Create a new <see cref="OtherHashAlgAndValue"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="hashValue">The hash value.</param>
        public OtherHashAlgAndValue(AlgorithmIdentifier hashAlgorithm, Asn1OctetString hashValue)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_hashValue = hashValue ?? throw new ArgumentNullException(nameof(hashValue));
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Return the hash value.</summary>
        public byte[] GetHashValue() => m_hashValue.GetOctets();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_hashAlgorithm, m_hashValue);
    }
}
