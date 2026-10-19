using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The DSA domain parameters p, q and g.</summary>
    public class DsaParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="DsaParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DsaParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DsaParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DsaParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DsaParameter dsaParameter)
                return dsaParameter;
            return new DsaParameter(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DsaParameter"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DsaParameter"/>.</returns>
        public static DsaParameter GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new DsaParameter(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="DsaParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DsaParameter"/>.</returns>
        public static DsaParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DsaParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_p, m_q, m_g;

        /// <summary>Create a new <see cref="DsaParameter"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="q">The q.</param>
        /// <param name="g">The g.</param>
        public DsaParameter(BigInteger p, BigInteger q, BigInteger g)
        {
            m_p = new DerInteger(p);
            m_q = new DerInteger(q);
            m_g = new DerInteger(g);
        }

        private DsaParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_p = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_q = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_g = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the p.</summary>
        public BigInteger P => m_p.PositiveValue;

        /// <summary>Gets the q.</summary>
        public BigInteger Q => m_q.PositiveValue;

        /// <summary>Gets the g.</summary>
        public BigInteger G => m_g.PositiveValue;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_p, m_q, m_g);
    }
}
