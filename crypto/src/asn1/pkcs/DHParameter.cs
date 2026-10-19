using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The DHParameter structure of PKCS#3: Diffie-Hellman parameters.</summary>
    public class DHParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="DHParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DHParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DHParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DHParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DHParameter dhParameter)
                return dhParameter;
#pragma warning disable CS0618 // Type or member is obsolete
            return new DHParameter(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="DHParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DHParameter"/>.</returns>
        public static DHParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DHParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="DHParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DHParameter"/>.</returns>
        public static DHParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DHParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_p, m_g, m_l;

        /// <summary>Create a new <see cref="DHParameter"/>.</summary>
        /// <param name="p">The prime modulus.</param>
        /// <param name="g">The generator.</param>
        /// <param name="l">The l.</param>
        public DHParameter(BigInteger p, BigInteger g, int l)
        {
            m_p = new DerInteger(p);
            m_g = new DerInteger(g);

            if (l != 0)
            {
                m_l = DerInteger.ValueOf(l);
            }
        }

        /// <summary>Create a new <see cref="DHParameter"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public DHParameter(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_p = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_g = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_l = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the p.</summary>
        public BigInteger P => m_p.PositiveValue;

        /// <summary>Gets the g.</summary>
        public BigInteger G => m_g.PositiveValue;

        /// <summary>Gets the l.</summary>
        public BigInteger L => m_l?.PositiveValue;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return m_l == null
                ?  new DerSequence(m_p, m_g)
                :  new DerSequence(m_p, m_g, m_l);
        }
    }
}
