using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>
    /// The KEKIdentifier structure of RFC 5652, identifying a previously distributed key encryption key.
    /// </summary>
    public class KekIdentifier
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="KekIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KekIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KekIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
        public static KekIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KekIdentifier kekIdentifier)
                return kekIdentifier;
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="KekIdentifier"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KekIdentifier"/>.</returns>
        public static KekIdentifier GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="KekIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KekIdentifier"/>.</returns>
        public static KekIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_keyIdentifier;
        private readonly Asn1GeneralizedTime m_date;
        private readonly OtherKeyAttribute m_other;

        /// <summary>Create a new <see cref="KekIdentifier"/>.</summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="date">The date.</param>
        /// <param name="other">The other.</param>
        public KekIdentifier(byte[] keyIdentifier, Asn1GeneralizedTime date, OtherKeyAttribute other)
        {
            m_keyIdentifier = DerOctetString.FromContents(keyIdentifier);
            m_date = date;
            m_other = other;
        }

        /// <summary>Create a new <see cref="KekIdentifier"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public KekIdentifier(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyIdentifier = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_date = Asn1Utilities.ReadOptional(seq, ref pos, Asn1GeneralizedTime.GetOptional);
            m_other = Asn1Utilities.ReadOptional(seq, ref pos, OtherKeyAttribute.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the key identifier.</summary>
        public Asn1OctetString KeyIdentifier => m_keyIdentifier;

        /// <summary>Gets the date.</summary>
        public Asn1GeneralizedTime Date => m_date;

        public OtherKeyAttribute Other => m_other;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * KekIdentifier ::= Sequence {
         *     keyIdentifier OCTET STRING,
         *     date GeneralizedTime OPTIONAL,
         *     other OtherKeyAttribute OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_keyIdentifier);
            v.AddOptional(m_date, m_other);
            return new DerSequence(v);
        }
    }
}

