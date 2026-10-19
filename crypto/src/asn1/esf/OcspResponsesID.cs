using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OcspResponsesID ::= SEQUENCE {
    /// ocspIdentifier OcspIdentifier,
    /// ocspRepHash OtherHash OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class OcspResponsesID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OcspResponsesID"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OcspResponsesID"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OcspResponsesID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OcspResponsesID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspResponsesID ocspResponsesID)
                return ocspResponsesID;
            return new OcspResponsesID(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OcspResponsesID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspResponsesID"/>.</returns>
        public static OcspResponsesID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspResponsesID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OcspResponsesID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspResponsesID"/>.</returns>
        public static OcspResponsesID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspResponsesID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OcspIdentifier m_ocspIdentifier;
        private readonly OtherHash m_ocspRepHash;

        private OcspResponsesID(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ocspIdentifier = Asn1Utilities.Read(seq, ref pos, OcspIdentifier.GetInstance);
            m_ocspRepHash = Asn1Utilities.ReadOptional(seq, ref pos, OtherHash.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OcspResponsesID"/>.</summary>
        /// <param name="ocspIdentifier">The ocsp identifier.</param>
        public OcspResponsesID(OcspIdentifier ocspIdentifier)
            : this(ocspIdentifier, null)
        {
        }

        /// <summary>Create a new <see cref="OcspResponsesID"/>.</summary>
        /// <param name="ocspIdentifier">The ocsp identifier.</param>
        /// <param name="ocspRepHash">The ocsp rep hash.</param>
        public OcspResponsesID(OcspIdentifier ocspIdentifier, OtherHash ocspRepHash)
        {
            m_ocspIdentifier = ocspIdentifier ?? throw new ArgumentNullException(nameof(ocspIdentifier));
            m_ocspRepHash = ocspRepHash;
        }

        public OcspIdentifier OcspIdentifier => m_ocspIdentifier;

        /// <summary>Gets the ocsp rep hash.</summary>
        public OtherHash OcspRepHash => m_ocspRepHash;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_ocspIdentifier);
            v.AddOptional(m_ocspRepHash);
            return new DerSequence(v);
        }
    }
}
