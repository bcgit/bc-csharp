using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.3.2 Revocation Values Attribute Definition
    /// <code>
    /// OtherRevVals ::= SEQUENCE
    /// {
    /// otherRevValType      OtherRevValType,
    /// otherRevVals         ANY DEFINED BY otherRevValType
    /// }
    ///
    /// OtherRevValType ::= OBJECT IDENTIFIER
    /// </code>
    /// </remarks>
    public class OtherRevVals
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OtherRevVals"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OtherRevVals"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OtherRevVals"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OtherRevVals GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherRevVals otherRevVals)
                return otherRevVals;
            return new OtherRevVals(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OtherRevVals"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherRevVals"/>.</returns>
        public static OtherRevVals GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OtherRevVals(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="OtherRevVals"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherRevVals"/>.</returns>
        public static OtherRevVals GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRevVals(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_otherRevValType;
        private readonly Asn1Encodable m_otherRevVals;

        private OtherRevVals(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_otherRevValType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_otherRevVals = Asn1Utilities.Read(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OtherRevVals"/>.</summary>
        /// <param name="otherRevValType">The other rev val type.</param>
        /// <param name="otherRevVals">The other rev vals.</param>
        public OtherRevVals(DerObjectIdentifier otherRevValType, Asn1Encodable otherRevVals)
        {
            m_otherRevValType = otherRevValType ?? throw new ArgumentNullException(nameof(otherRevValType));
            m_otherRevVals = otherRevVals ?? throw new ArgumentNullException(nameof(otherRevVals));
        }

        /// <summary>Gets the other rev val type.</summary>
        public DerObjectIdentifier OtherRevValType => m_otherRevValType;

        /// <summary>Gets the other rev vals data.</summary>
        public Asn1Encodable OtherRevValsData => m_otherRevVals;

        /// <summary>Gets the other rev vals object.</summary>
        [Obsolete("Use 'OtherRevValsData' instead")]
        public Asn1Object OtherRevValsObject => m_otherRevVals.ToAsn1Object();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_otherRevValType, m_otherRevVals);
    }
}
