using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The OriginatorInfo structure of RFC 5652: certificates and CRLs of the message originator.</summary>
    public class OriginatorInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OriginatorInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OriginatorInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OriginatorInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OriginatorInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OriginatorInfo originatorInfo)
                return originatorInfo;
#pragma warning disable CS0618 // Type or member is obsolete
            return new OriginatorInfo(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="OriginatorInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OriginatorInfo"/>.</returns>
        public static OriginatorInfo GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OriginatorInfo(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="OriginatorInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OriginatorInfo"/>.</returns>
        public static OriginatorInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new OriginatorInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Set m_certs;
        private readonly Asn1Set m_crls;

        /// <summary>Create a new <see cref="OriginatorInfo"/>.</summary>
        /// <param name="certs">The certs.</param>
        /// <param name="crls">The crls.</param>
        public OriginatorInfo(Asn1Set certs, Asn1Set crls)
        {
            m_certs = certs;
            m_crls = crls;
        }

        /// <summary>Create a new <see cref="OriginatorInfo"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public OriginatorInfo(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 0 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetTagged);
            m_crls = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the certificates.</summary>
        public Asn1Set Certificates => m_certs;

        /// <summary>Gets the crls.</summary>
        public Asn1Set Crls => m_crls;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OriginatorInfo ::= Sequence {
         *     certs [0] IMPLICIT CertificateSet OPTIONAL,
         *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_certs);
            v.AddOptionalTagged(false, 1, m_crls);
            return new DerSequence(v);
        }
    }
}
