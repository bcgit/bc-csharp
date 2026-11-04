using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * GenMsg:    {id-it 20}, RootCaCertValue | &lt; absent &gt;
     * GenRep:    {id-it 18}, RootCaKeyUpdateContent | &lt; absent &gt;
     * <p>
     * RootCaCertValue ::= CMPCertificate
     * </p><p>
     * RootCaKeyUpdateValue ::= RootCaKeyUpdateContent
     * </p><p>
     * RootCaKeyUpdateContent ::= SEQUENCE {
     * newWithNew       CMPCertificate,
     * newWithOld   [0] CMPCertificate OPTIONAL,
     * oldWithNew   [1] CMPCertificate OPTIONAL
     * }
     * </p>
     */
    public class RootCaKeyUpdateContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RootCaKeyUpdateContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RootCaKeyUpdateContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RootCaKeyUpdateContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RootCaKeyUpdateContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RootCaKeyUpdateContent rootCaKeyUpdateContent)
                return rootCaKeyUpdateContent;
            return new RootCaKeyUpdateContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RootCaKeyUpdateContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RootCaKeyUpdateContent"/>.</returns>
        public static RootCaKeyUpdateContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RootCaKeyUpdateContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="RootCaKeyUpdateContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RootCaKeyUpdateContent"/>.</returns>
        public static RootCaKeyUpdateContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RootCaKeyUpdateContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CmpCertificate m_newWithNew;
        private readonly CmpCertificate m_newWithOld;
        private readonly CmpCertificate m_oldWithNew;

        /// <summary>Create a new <see cref="RootCaKeyUpdateContent"/>.</summary>
        /// <param name="newWithNew">The new with new.</param>
        /// <param name="newWithOld">The new with old.</param>
        /// <param name="oldWithNew">The old with new.</param>
        public RootCaKeyUpdateContent(CmpCertificate newWithNew, CmpCertificate newWithOld, CmpCertificate oldWithNew)
        {
            m_newWithNew = newWithNew ?? throw new ArgumentNullException(nameof(newWithNew));
            m_newWithOld = newWithOld;
            m_oldWithNew = oldWithNew;
        }

        private RootCaKeyUpdateContent(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_newWithNew = Asn1Utilities.Read(seq, ref pos, CmpCertificate.GetInstance);
            m_newWithOld = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, CmpCertificate.GetTagged);
            m_oldWithNew = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, CmpCertificate.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the new with new.</summary>
        public virtual CmpCertificate NewWithNew => m_newWithNew;

        /// <summary>Gets the new with old.</summary>
        public virtual CmpCertificate NewWithOld => m_newWithOld;

        /// <summary>Gets the old with new.</summary>
        public virtual CmpCertificate OldWithNew => m_oldWithNew;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_newWithNew);
            v.AddOptionalTagged(true, 0, m_newWithOld);
            v.AddOptionalTagged(true, 1, m_oldWithNew);
            return new DerSequence(v);
        }
    }
}
