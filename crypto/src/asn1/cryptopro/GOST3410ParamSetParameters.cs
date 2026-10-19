using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    /// <summary>The parameters of a GOST R 34.10-94 parameter set.</summary>
    public class Gost3410ParamSetParameters
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Gost3410ParamSetParameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Gost3410ParamSetParameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Gost3410ParamSetParameters"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Gost3410ParamSetParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Gost3410ParamSetParameters gost3410ParamSetParameters)
                return gost3410ParamSetParameters;
            return new Gost3410ParamSetParameters(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Gost3410ParamSetParameters"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Gost3410ParamSetParameters"/>.</returns>
        public static Gost3410ParamSetParameters GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new Gost3410ParamSetParameters(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="Gost3410ParamSetParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Gost3410ParamSetParameters"/>.</returns>
        public static Gost3410ParamSetParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost3410ParamSetParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly int m_keySize;
        private readonly DerInteger m_p, m_q, m_a;

        private Gost3410ParamSetParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keySize = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).IntValueExact;
            m_p = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_q = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_a = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Gost3410ParamSetParameters"/>.</summary>
        /// <param name="keySize">The key size in bits.</param>
        /// <param name="p">The p.</param>
        /// <param name="q">The q.</param>
        /// <param name="a">The first operand.</param>
        public Gost3410ParamSetParameters(int keySize, BigInteger p, BigInteger q, BigInteger a)
        {
            m_keySize = keySize;
            m_p = new DerInteger(p);
            m_q = new DerInteger(q);
            m_a = new DerInteger(a);
        }

        /// <summary>Gets the key size.</summary>
        public int KeySize => m_keySize;

        /// <summary>Gets the p.</summary>
        public BigInteger P => m_p.PositiveValue;

        /// <summary>Gets the q.</summary>
        public BigInteger Q => m_q.PositiveValue;

        /// <summary>Gets the a.</summary>
        public BigInteger A => m_a.PositiveValue;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(DerInteger.ValueOf(m_keySize), m_p, m_q, m_a);
    }
}
