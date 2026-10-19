using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Oiw
{
    /// <summary>The ElGamal parameters: a prime p and a generator g.</summary>
    public class ElGamalParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ElGamalParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ElGamalParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ElGamalParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ElGamalParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ElGamalParameter elGamalParameter)
                return elGamalParameter;
#pragma warning disable CS0618 // Type or member is obsolete
            return new ElGamalParameter(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="ElGamalParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ElGamalParameter"/>.</returns>
        public static ElGamalParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new ElGamalParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="ElGamalParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ElGamalParameter"/>.</returns>
        public static ElGamalParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new ElGamalParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_p, m_g;

        /// <summary>Create a new <see cref="ElGamalParameter"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public ElGamalParameter(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_p = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_g = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="ElGamalParameter"/>.</summary>
        /// <param name="p">The prime modulus.</param>
        /// <param name="g">The generator.</param>
        public ElGamalParameter(BigInteger p, BigInteger g)
        {
            m_p = new DerInteger(p);
            m_g = new DerInteger(g);
        }

        /// <summary>Gets the p.</summary>
        public BigInteger P => m_p.PositiveValue;

        /// <summary>Gets the g.</summary>
        public BigInteger G => m_g.PositiveValue;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_p, m_g);
    }
}
