using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The OtherRevocationInfoFormat structure of RFC 5652.</summary>
    public class OtherRevocationInfoFormat
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OtherRevocationInfoFormat"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OtherRevocationInfoFormat"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OtherRevocationInfoFormat"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OtherRevocationInfoFormat GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherRevocationInfoFormat otherRevocationInfoFormat)
                return otherRevocationInfoFormat;
            return new OtherRevocationInfoFormat(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OtherRevocationInfoFormat"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherRevocationInfoFormat"/>.</returns>
        public static OtherRevocationInfoFormat GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new OtherRevocationInfoFormat(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="OtherRevocationInfoFormat"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherRevocationInfoFormat"/>.</returns>
        public static OtherRevocationInfoFormat GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherRevocationInfoFormat(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_otherRevInfoFormat;
        private readonly Asn1Encodable m_otherRevInfo;

        /// <summary>Create a new <see cref="OtherRevocationInfoFormat"/>.</summary>
        /// <param name="otherRevInfoFormat">The other rev info format.</param>
        /// <param name="otherRevInfo">The other rev info.</param>
        public OtherRevocationInfoFormat(DerObjectIdentifier otherRevInfoFormat, Asn1Encodable otherRevInfo)
        {
            m_otherRevInfoFormat = otherRevInfoFormat ?? throw new ArgumentNullException(nameof(otherRevInfoFormat));
            m_otherRevInfo = otherRevInfo ?? throw new ArgumentNullException(nameof(otherRevInfo));
        }

        private OtherRevocationInfoFormat(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_otherRevInfoFormat = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_otherRevInfo = Asn1Utilities.Read(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the info format.</summary>
        public virtual DerObjectIdentifier InfoFormat => m_otherRevInfoFormat;

        /// <summary>Gets the info.</summary>
        public virtual Asn1Encodable Info => m_otherRevInfo;

        /**
         * Produce an object suitable for an ASN1OutputStream.
         * <pre>
         * OtherRevocationInfoFormat ::= SEQUENCE {
         *      otherRevInfoFormat OBJECT IDENTIFIER,
         *      otherRevInfo ANY DEFINED BY otherRevInfoFormat }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_otherRevInfoFormat, m_otherRevInfo);
    }
}
