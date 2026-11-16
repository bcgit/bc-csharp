using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The Validity structure of RFC 5280: the first and last times at which a certificate is valid.</summary>
    public class Validity
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Validity"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Validity"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Validity"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Validity GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Validity validity)
                return validity;
            return new Validity(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Validity"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Validity"/>.</returns>
        public static Validity GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Validity(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Validity"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Validity"/>.</returns>
        public static Validity GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Validity(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Time m_notBefore;
        private readonly Time m_notAfter;

        private Validity(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_notBefore = Asn1Utilities.Read(seq, ref pos, Time.GetInstance);
            m_notAfter = Asn1Utilities.Read(seq, ref pos, Time.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Validity"/>.</summary>
        /// <param name="notBefore">The not before.</param>
        /// <param name="notAfter">The not after.</param>
        public Validity(Time notBefore, Time notAfter)
        {
            m_notBefore = notBefore ?? throw new ArgumentNullException(nameof(notBefore));
            m_notAfter = notAfter ?? throw new ArgumentNullException(nameof(notAfter));
        }

        /// <summary>Gets the not before.</summary>
        public Time NotBefore => m_notBefore;

        /// <summary>Gets the not after.</summary>
        public Time NotAfter => m_notAfter;

        /**
         * <pre>
         * Validity ::= SEQUENCE {
         *   notBefore      Time,
         *   notAfter       Time  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_notBefore, m_notAfter);
    }
}
