using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The PKCS12PBEParams structure of PKCS#12: a salt and an iteration count.</summary>
    public class Pkcs12PbeParams
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Pkcs12PbeParams"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Pkcs12PbeParams"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Pkcs12PbeParams"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Pkcs12PbeParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Pkcs12PbeParams pkcs12PbeParams)
                return pkcs12PbeParams;
            return new Pkcs12PbeParams(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Pkcs12PbeParams"/> from a tagged object.</summary>
        /// <param name="tagged">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Pkcs12PbeParams"/>.</returns>
        public static Pkcs12PbeParams GetInstance(Asn1TaggedObject tagged, bool declaredExplicit) =>
            new Pkcs12PbeParams(Asn1Sequence.GetInstance(tagged, declaredExplicit));

        /// <summary>Return an <see cref="Pkcs12PbeParams"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Pkcs12PbeParams"/>.</returns>
        public static Pkcs12PbeParams GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pkcs12PbeParams(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_iv;
        private readonly DerInteger m_iterations;

        private Pkcs12PbeParams(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_iv = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_iterations = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Pkcs12PbeParams"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The iterations.</param>
        public Pkcs12PbeParams(byte[] salt, int iterations)
        {
            m_iv = DerOctetString.FromContents(salt);
            m_iterations = DerInteger.ValueOf(iterations);
        }

        /// <summary>Gets the iterations.</summary>
        public BigInteger Iterations => m_iterations.Value;

        /// <summary>Gets the iterations object.</summary>
        public DerInteger IterationsObject => m_iterations;

        /// <summary>Return the IV.</summary>
        public byte[] GetIV() => m_iv.GetOctets();

        /// <summary>Gets the IV.</summary>
        public Asn1OctetString IV => m_iv;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_iv, m_iterations);
    }
}
