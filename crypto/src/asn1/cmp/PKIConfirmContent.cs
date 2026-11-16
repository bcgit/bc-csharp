using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  PKIConfirmContent ::= NULL
     */
    public class PkiConfirmContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PkiConfirmContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PkiConfirmContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PkiConfirmContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiConfirmContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiConfirmContent pkiConfirmContent)
                return pkiConfirmContent;
            return new PkiConfirmContent(Asn1Null.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PkiConfirmContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiConfirmContent"/>.</returns>
        public static PkiConfirmContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiConfirmContent(Asn1Null.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PkiConfirmContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiConfirmContent"/>.</returns>
        public static PkiConfirmContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiConfirmContent(Asn1Null.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Null m_val;

        /// <summary>Create a new <see cref="PkiConfirmContent"/>.</summary>
        public PkiConfirmContent()
            : this(DerNull.Instance)
        {
        }

        private PkiConfirmContent(Asn1Null val)
        {
            m_val = val;
        }

        /**
         * <pre>
         * PkiConfirmContent ::= NULL
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_val;
    }
}
