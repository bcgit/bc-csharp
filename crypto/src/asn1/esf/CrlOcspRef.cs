using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CrlOcspRef ::= SEQUENCE {
    /// crlids [0] CRLListID OPTIONAL,
    /// 	ocspids [1] OcspListID OPTIONAL,
    /// 	otherRev [2] OtherRevRefs OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class CrlOcspRef
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlOcspRef"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CrlOcspRef"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CrlOcspRef"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlOcspRef GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlOcspRef crlOcspRef)
                return crlOcspRef;
            return new CrlOcspRef(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CrlOcspRef"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlOcspRef"/>.</returns>
        public static CrlOcspRef GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlOcspRef(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CrlOcspRef"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlOcspRef"/>.</returns>
        public static CrlOcspRef GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlOcspRef(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CrlListID m_crlids;
        private readonly OcspListID m_ocspids;
        private readonly OtherRevRefs m_otherRev;

        private CrlOcspRef(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_crlids = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, CrlListID.GetTagged);
            m_ocspids = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, OcspListID.GetTagged);
            m_otherRev = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, OtherRevRefs.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CrlOcspRef"/>.</summary>
        /// <param name="crlids">The crlids.</param>
        /// <param name="ocspids">The ocspids.</param>
        /// <param name="otherRev">The other rev.</param>
        public CrlOcspRef(CrlListID crlids, OcspListID ocspids, OtherRevRefs otherRev)
        {
            m_crlids = crlids;
            m_ocspids = ocspids;
            m_otherRev = otherRev;
        }

        /// <summary>Gets the crl i ds.</summary>
        public CrlListID CrlIDs => m_crlids;

        /// <summary>Gets the ocsp i ds.</summary>
        public OcspListID OcspIDs => m_ocspids;

        public OtherRevRefs OtherRev => m_otherRev;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_crlids);
            v.AddOptionalTagged(true, 1, m_ocspids);
            v.AddOptionalTagged(true, 2, m_otherRev);
            return DerSequence.FromVector(v);
        }
    }
}
