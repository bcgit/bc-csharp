using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The AttCertValidityPeriod structure of RFC 5755.</summary>
    public class AttCertValidityPeriod
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AttCertValidityPeriod"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AttCertValidityPeriod"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AttCertValidityPeriod"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AttCertValidityPeriod GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttCertValidityPeriod attCertValidityPeriod)
                return attCertValidityPeriod;
            return new AttCertValidityPeriod(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AttCertValidityPeriod"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttCertValidityPeriod"/>.</returns>
        public static AttCertValidityPeriod GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new AttCertValidityPeriod(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="AttCertValidityPeriod"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttCertValidityPeriod"/>.</returns>
        public static AttCertValidityPeriod GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttCertValidityPeriod(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1GeneralizedTime m_notBeforeTime;
        private readonly Asn1GeneralizedTime m_notAfterTime;

        private AttCertValidityPeriod(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_notBeforeTime = Asn1Utilities.Read(seq, ref pos, Asn1GeneralizedTime.GetInstance);
            m_notAfterTime = Asn1Utilities.Read(seq, ref pos, Asn1GeneralizedTime.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="AttCertValidityPeriod"/>.</summary>
        /// <param name="notBeforeTime">The not before time.</param>
        /// <param name="notAfterTime">The not after time.</param>
        public AttCertValidityPeriod(Asn1GeneralizedTime notBeforeTime, Asn1GeneralizedTime notAfterTime)
        {
            m_notBeforeTime = notBeforeTime ?? throw new ArgumentNullException(nameof(notBeforeTime));
            m_notAfterTime = notAfterTime ?? throw new ArgumentNullException(nameof(notAfterTime));
        }

        /// <summary>Gets the not before time.</summary>
        public Asn1GeneralizedTime NotBeforeTime => m_notBeforeTime;

        /// <summary>Gets the not after time.</summary>
        public Asn1GeneralizedTime NotAfterTime => m_notAfterTime;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  AttCertValidityPeriod  ::= Sequence {
         *       notBeforeTime  GeneralizedTime,
         *       notAfterTime   GeneralizedTime
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_notBeforeTime, m_notAfterTime);
    }
}
