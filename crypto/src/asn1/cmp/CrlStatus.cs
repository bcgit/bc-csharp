using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * CRLStatus ::= SEQUENCE {
     * source       CRLSource,
     * thisUpdate   Time OPTIONAL }
     */
    public class CrlStatus
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlStatus"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CrlStatus"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CrlStatus"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlStatus GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlStatus crlStatus)
                return crlStatus;
            return new CrlStatus(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CrlStatus"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlStatus"/>.</returns>
        public static CrlStatus GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlStatus(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CrlStatus"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlStatus"/>.</returns>
        public static CrlStatus GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlStatus(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CrlSource m_source;
        private readonly Time m_thisUpdate;

        private CrlStatus(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_source = Asn1Utilities.Read(seq, ref pos, CrlSource.GetInstance);
            m_thisUpdate = Asn1Utilities.ReadOptional(seq, ref pos, Time.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CrlStatus"/>.</summary>
        /// <param name="source">The source.</param>
        /// <param name="thisUpdate">The this update.</param>
        public CrlStatus(CrlSource source, Time thisUpdate)
        {
            m_source = source ?? throw new ArgumentNullException(nameof(source));
            m_thisUpdate = thisUpdate;
        }

        /// <summary>Gets the source.</summary>
        public virtual CrlSource Source => m_source;

        /// <summary>Gets the this update.</summary>
        public virtual Time ThisUpdate => m_thisUpdate;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return m_thisUpdate == null
                ?  new DerSequence(m_source)
                :  new DerSequence(m_source, m_thisUpdate);
        }
    }
}
