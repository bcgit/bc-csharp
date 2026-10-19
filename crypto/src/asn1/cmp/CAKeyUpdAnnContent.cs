using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CAKeyUpdAnnContent structure of RFC 4210, the body of a CA key update announcement.</summary>
    public class CAKeyUpdAnnContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CAKeyUpdAnnContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CAKeyUpdAnnContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CAKeyUpdAnnContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CAKeyUpdAnnContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CAKeyUpdAnnContent caKeyUpdAnnContent)
                return caKeyUpdAnnContent;
            return new CAKeyUpdAnnContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CAKeyUpdAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CAKeyUpdAnnContent"/>.</returns>
        public static CAKeyUpdAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CAKeyUpdAnnContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CAKeyUpdAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CAKeyUpdAnnContent"/>.</returns>
        public static CAKeyUpdAnnContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CAKeyUpdAnnContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CmpCertificate m_oldWithNew;
        private readonly CmpCertificate m_newWithOld;
        private readonly CmpCertificate m_newWithNew;

        private CAKeyUpdAnnContent(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_oldWithNew = Asn1Utilities.Read(seq, ref pos, CmpCertificate.GetInstance);
            m_newWithOld = Asn1Utilities.Read(seq, ref pos, CmpCertificate.GetInstance);
            m_newWithNew = Asn1Utilities.Read(seq, ref pos, CmpCertificate.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the old with new.</summary>
        public virtual CmpCertificate OldWithNew => m_oldWithNew;

        /// <summary>Gets the new with old.</summary>
        public virtual CmpCertificate NewWithOld => m_newWithOld;

        /// <summary>Gets the new with new.</summary>
        public virtual CmpCertificate NewWithNew => m_newWithNew;

        /**
         * <pre>
         * CAKeyUpdAnnContent ::= SEQUENCE {
         *                             oldWithNew   CmpCertificate, -- old pub signed with new priv
         *                             newWithOld   CmpCertificate, -- new pub signed with old priv
         *                             newWithNew   CmpCertificate  -- new pub signed with new priv
         *  }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_oldWithNew, m_newWithOld, m_newWithNew);
    }
}
