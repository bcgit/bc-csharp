using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.1 Complete Certificate Refs Attribute Definition
    /// <code>
    /// CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
    /// </code>
    /// </remarks>
    public class CompleteCertificateRefs
        : Asn1Encodable
    {
        public static CompleteCertificateRefs GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CompleteCertificateRefs completeCertificateRefs)
                return completeCertificateRefs;
            return new CompleteCertificateRefs(Asn1Sequence.GetInstance(obj));
        }

        public static CompleteCertificateRefs GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CompleteCertificateRefs(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CompleteCertificateRefs GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CompleteCertificateRefs(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_otherCertIDs;

        private CompleteCertificateRefs(Asn1Sequence seq)
        {
            m_otherCertIDs = seq;
            m_otherCertIDs.MapElements(OtherCertID.GetInstance); // Validate
        }

        public CompleteCertificateRefs(params OtherCertID[] otherCertIDs)
        {
            m_otherCertIDs = DerSequence.FromElements(otherCertIDs);
        }

        public CompleteCertificateRefs(IEnumerable<OtherCertID> otherCertIDs)
        {
            if (otherCertIDs == null)
                throw new ArgumentNullException(nameof(otherCertIDs));

            m_otherCertIDs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(otherCertIDs));
        }

        public CompleteCertificateRefs(IReadOnlyCollection<OtherCertID> otherCertIDs)
        {
            if (otherCertIDs == null)
                throw new ArgumentNullException(nameof(otherCertIDs));

            m_otherCertIDs = DerSequence.FromCollection(otherCertIDs);
        }

        public OtherCertID[] GetOtherCertIDs() => m_otherCertIDs.MapElements(OtherCertID.GetInstance);

        public override Asn1Object ToAsn1Object() => m_otherCertIDs;
    }
}
