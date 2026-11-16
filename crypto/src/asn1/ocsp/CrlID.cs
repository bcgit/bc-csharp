using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The CrlID structure of RFC 6960.</summary>
    public class CrlID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlID"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CrlID"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CrlID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlID crlID)
                return crlID;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlID(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CrlID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlID"/>.</returns>
        public static CrlID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CrlID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlID"/>.</returns>
        public static CrlID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerIA5String m_crlUrl;
        private readonly DerInteger m_crlNum;
        private readonly Asn1GeneralizedTime m_crlTime;

        /// <summary>Create a new <see cref="CrlID"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public CrlID(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_crlUrl = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerIA5String.GetTagged);
            m_crlNum = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, DerInteger.GetTagged);
            m_crlTime = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, Asn1GeneralizedTime.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the crl url.</summary>
        public DerIA5String CrlUrl => m_crlUrl;

        /// <summary>Gets the crl num.</summary>
        public DerInteger CrlNum => m_crlNum;

        /// <summary>Gets the crl time.</summary>
        public Asn1GeneralizedTime CrlTime => m_crlTime;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * CrlID ::= Sequence {
         *     crlUrl               [0]     EXPLICIT IA5String OPTIONAL,
         *     crlNum               [1]     EXPLICIT Integer OPTIONAL,
         *     crlTime              [2]     EXPLICIT GeneralizedTime OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_crlUrl);
            v.AddOptionalTagged(true, 1, m_crlNum);
            v.AddOptionalTagged(true, 2, m_crlTime);
            return new DerSequence(v);
        }
    }
}
