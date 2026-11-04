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
        /// <summary>Return an <see cref="CompleteCertificateRefs"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CompleteCertificateRefs"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CompleteCertificateRefs"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CompleteCertificateRefs GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CompleteCertificateRefs completeCertificateRefs)
                return completeCertificateRefs;
            return new CompleteCertificateRefs(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CompleteCertificateRefs"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CompleteCertificateRefs"/>.</returns>
        public static CompleteCertificateRefs GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CompleteCertificateRefs(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CompleteCertificateRefs"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CompleteCertificateRefs"/>.</returns>
        public static CompleteCertificateRefs GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CompleteCertificateRefs(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_otherCertIDs;

        private CompleteCertificateRefs(Asn1Sequence seq)
        {
            m_otherCertIDs = seq;
            m_otherCertIDs.MapElements(OtherCertID.GetInstance); // Validate
        }

        /// <summary>Create a new <see cref="CompleteCertificateRefs"/>.</summary>
        /// <param name="otherCertIDs">The other cert i ds.</param>
        public CompleteCertificateRefs(params OtherCertID[] otherCertIDs)
        {
            m_otherCertIDs = DerSequence.FromElements(otherCertIDs);
        }

        /// <summary>Create a new <see cref="CompleteCertificateRefs"/>.</summary>
        /// <param name="otherCertIDs">The other cert i ds.</param>
        public CompleteCertificateRefs(IEnumerable<OtherCertID> otherCertIDs)
        {
            if (otherCertIDs == null)
                throw new ArgumentNullException(nameof(otherCertIDs));

            m_otherCertIDs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(otherCertIDs));
        }

        /// <summary>Create a new <see cref="CompleteCertificateRefs"/>.</summary>
        /// <param name="otherCertIDs">The other cert i ds.</param>
        public CompleteCertificateRefs(IReadOnlyCollection<OtherCertID> otherCertIDs)
        {
            if (otherCertIDs == null)
                throw new ArgumentNullException(nameof(otherCertIDs));

            m_otherCertIDs = DerSequence.FromCollection(otherCertIDs);
        }

        /// <summary>Return the other cert i ds.</summary>
        public OtherCertID[] GetOtherCertIDs() => m_otherCertIDs.MapElements(OtherCertID.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_otherCertIDs;
    }
}
