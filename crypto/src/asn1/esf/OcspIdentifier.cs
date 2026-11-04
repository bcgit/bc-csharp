using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OcspIdentifier ::= SEQUENCE {
    /// ocspResponderID ResponderID,
    /// -- As in OCSP response data
    /// producedAt GeneralizedTime
    /// -- As in OCSP response data
    /// }
    /// </code>
    /// </remarks>
    public class OcspIdentifier
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OcspIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OcspIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OcspIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OcspIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspIdentifier ocspIdentifier)
                return ocspIdentifier;
            return new OcspIdentifier(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OcspIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspIdentifier"/>.</returns>
        public static OcspIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspIdentifier(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OcspIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspIdentifier"/>.</returns>
        public static OcspIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ResponderID m_ocspResponderID;
        private readonly Asn1GeneralizedTime m_producedAt;

        private OcspIdentifier(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ocspResponderID = Asn1Utilities.Read(seq, ref pos, ResponderID.GetInstance);
            m_producedAt = Asn1Utilities.Read(seq, ref pos, Asn1GeneralizedTime.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OcspIdentifier"/>.</summary>
        /// <param name="ocspResponderID">The ocsp responder ID.</param>
        /// <param name="producedAt">The produced at.</param>
        public OcspIdentifier(ResponderID ocspResponderID, DateTime producedAt)
            : this(ocspResponderID, Rfc5280Asn1Utilities.CreateGeneralizedTime(producedAt))
        {
        }

        /// <summary>Create a new <see cref="OcspIdentifier"/>.</summary>
        /// <param name="ocspResponderID">The ocsp responder ID.</param>
        /// <param name="producedAt">The produced at.</param>
        public OcspIdentifier(ResponderID ocspResponderID, Asn1GeneralizedTime producedAt)
        {
            m_ocspResponderID = ocspResponderID ?? throw new ArgumentNullException(nameof(ocspResponderID));
            m_producedAt = producedAt ?? throw new ArgumentNullException(nameof(producedAt));
        }

        /// <summary>Gets the ocsp responder ID.</summary>
        public ResponderID OcspResponderID => m_ocspResponderID;

        /// <summary>Gets the produced at data.</summary>
        public Asn1GeneralizedTime ProducedAtData => m_producedAt;

        /// <summary>Gets the produced at.</summary>
        public DateTime ProducedAt => m_producedAt.ToDateTime();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_ocspResponderID, m_producedAt);
    }
}
