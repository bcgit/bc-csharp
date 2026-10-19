using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
    /// </code>
    /// </remarks>
    public class CompleteRevocationRefs
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CompleteRevocationRefs"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CompleteRevocationRefs"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CompleteRevocationRefs"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CompleteRevocationRefs GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CompleteRevocationRefs completeRevocationRefs)
                return completeRevocationRefs;
            return new CompleteRevocationRefs(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CompleteRevocationRefs"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CompleteRevocationRefs"/>.</returns>
        public static CompleteRevocationRefs GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CompleteRevocationRefs(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CompleteRevocationRefs"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CompleteRevocationRefs"/>.</returns>
        public static CompleteRevocationRefs GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CompleteRevocationRefs(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_crlOcspRefs;

        private CompleteRevocationRefs(Asn1Sequence seq)
        {
            m_crlOcspRefs = seq;
            m_crlOcspRefs.MapElements(CrlOcspRef.GetInstance); // Validate
        }

        /// <summary>Create a new <see cref="CompleteRevocationRefs"/>.</summary>
        /// <param name="crlOcspRefs">The crl ocsp refs.</param>
        public CompleteRevocationRefs(params CrlOcspRef[] crlOcspRefs)
        {
            m_crlOcspRefs = DerSequence.FromElements(crlOcspRefs);
        }

        /// <summary>Create a new <see cref="CompleteRevocationRefs"/>.</summary>
        /// <param name="crlOcspRefs">The crl ocsp refs.</param>
        public CompleteRevocationRefs(IEnumerable<CrlOcspRef> crlOcspRefs)
        {
            if (crlOcspRefs == null)
                throw new ArgumentNullException(nameof(crlOcspRefs));

            m_crlOcspRefs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(crlOcspRefs));
        }

        /// <summary>Create a new <see cref="CompleteRevocationRefs"/>.</summary>
        /// <param name="crlOcspRefs">The crl ocsp refs.</param>
        public CompleteRevocationRefs(IReadOnlyCollection<CrlOcspRef> crlOcspRefs)
        {
            if (crlOcspRefs == null)
                throw new ArgumentNullException(nameof(crlOcspRefs));

            m_crlOcspRefs = DerSequence.FromCollection(crlOcspRefs);
        }

        /// <summary>Return the crl ocsp refs.</summary>
        public CrlOcspRef[] GetCrlOcspRefs() => m_crlOcspRefs.MapElements(CrlOcspRef.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_crlOcspRefs;
    }
}
