using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OcspListID ::=  SEQUENCE {
    ///		ocspResponses	SEQUENCE OF OcspResponsesID
    /// }
    /// </code>
    /// </remarks>
    public class OcspListID
        : Asn1Encodable
    {
        public static OcspListID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspListID ocspListID)
                return ocspListID;
            return new OcspListID(Asn1Sequence.GetInstance(obj));
        }

        public static OcspListID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspListID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OcspListID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspListID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_ocspResponses;

        private OcspListID(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ocspResponses = Asn1Sequence.GetInstance(seq[0]);
            m_ocspResponses.MapElements(OcspResponsesID.GetInstance); // Validate
        }

        public OcspListID(params OcspResponsesID[] ocspResponses)
        {
            m_ocspResponses = DerSequence.FromElements(ocspResponses);
        }

        public OcspListID(IEnumerable<OcspResponsesID> ocspResponses)
        {
            if (ocspResponses == null)
                throw new ArgumentNullException(nameof(ocspResponses));

            m_ocspResponses = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(ocspResponses));
        }

        public OcspListID(IReadOnlyCollection<OcspResponsesID> ocspResponses)
        {
            if (ocspResponses == null)
                throw new ArgumentNullException(nameof(ocspResponses));

            m_ocspResponses = DerSequence.FromCollection(ocspResponses);
        }

        public OcspResponsesID[] GetOcspResponses() => m_ocspResponses.MapElements(OcspResponsesID.GetInstance);

        public override Asn1Object ToAsn1Object() => DerSequence.FromElement(m_ocspResponses);
    }
}
