using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /**
     * ASN.1 def for Diffie-Hellman key exchange KeySpecificInfo structure. See
     * RFC 2631, or X9.42, for further details.
     */
    public class KeySpecificInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="KeySpecificInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KeySpecificInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KeySpecificInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static KeySpecificInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KeySpecificInfo keySpecificInfo)
                return keySpecificInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeySpecificInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="KeySpecificInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeySpecificInfo"/>.</returns>
        public static KeySpecificInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeySpecificInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="KeySpecificInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeySpecificInfo"/>.</returns>
        public static KeySpecificInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KeySpecificInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerObjectIdentifier m_algorithm;
        private readonly Asn1OctetString m_counter;

        /// <summary>Create a new <see cref="KeySpecificInfo"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public KeySpecificInfo(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algorithm = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_counter = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="KeySpecificInfo"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="counter">The counter.</param>
        public KeySpecificInfo(DerObjectIdentifier algorithm, Asn1OctetString counter)
        {
            m_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            m_counter = counter ?? throw new ArgumentNullException(nameof(counter));
        }

        /// <summary>Gets the algorithm.</summary>
        public DerObjectIdentifier Algorithm => m_algorithm;

        /// <summary>Gets the counter.</summary>
        public Asn1OctetString Counter => m_counter;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  KeySpecificInfo ::= Sequence {
         *      algorithm OBJECT IDENTIFIER,
         *      counter OCTET STRING SIZE (4..4)
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_algorithm, m_counter);
    }
}
