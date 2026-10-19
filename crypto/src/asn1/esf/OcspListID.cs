using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OcspListID ::=  SEQUENCE {
    /// ocspResponses SEQUENCE OF OcspResponsesID
    /// }
    /// </code>
    /// </remarks>
    public class OcspListID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OcspListID"/> from the given object.</summary>
        /// <param name="obj">An <see cref="OcspListID"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="OcspListID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OcspListID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspListID ocspListID)
                return ocspListID;
            return new OcspListID(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OcspListID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspListID"/>.</returns>
        public static OcspListID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspListID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OcspListID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspListID"/>.</returns>
        public static OcspListID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspListID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_ocspResponses;

        private OcspListID(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ocspResponses = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);
            m_ocspResponses.MapElements(OcspResponsesID.GetInstance); // Validate

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OcspListID"/>.</summary>
        /// <param name="ocspResponses">The ocsp responses.</param>
        public OcspListID(params OcspResponsesID[] ocspResponses)
        {
            m_ocspResponses = DerSequence.FromElements(ocspResponses);
        }

        /// <summary>Create a new <see cref="OcspListID"/>.</summary>
        /// <param name="ocspResponses">The ocsp responses.</param>
        public OcspListID(IEnumerable<OcspResponsesID> ocspResponses)
        {
            if (ocspResponses == null)
                throw new ArgumentNullException(nameof(ocspResponses));

            m_ocspResponses = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(ocspResponses));
        }

        /// <summary>Create a new <see cref="OcspListID"/>.</summary>
        /// <param name="ocspResponses">The ocsp responses.</param>
        public OcspListID(IReadOnlyCollection<OcspResponsesID> ocspResponses)
        {
            if (ocspResponses == null)
                throw new ArgumentNullException(nameof(ocspResponses));

            m_ocspResponses = DerSequence.FromCollection(ocspResponses);
        }

        /// <summary>Return the ocsp responses.</summary>
        public OcspResponsesID[] GetOcspResponses() => m_ocspResponses.MapElements(OcspResponsesID.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => DerSequence.FromElement(m_ocspResponses);
    }
}
