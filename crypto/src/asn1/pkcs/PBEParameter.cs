using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The PBEParameter structure of PKCS#5: a salt and an iteration count.</summary>
    public class PbeParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PbeParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PbeParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PbeParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PbeParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbeParameter pbeParameter)
                return pbeParameter;
            return new PbeParameter(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PbeParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbeParameter"/>.</returns>
        public static PbeParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PbeParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbeParameter"/>.</returns>
        public static PbeParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_salt;
        private readonly DerInteger m_iterationCount;

        private PbeParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_salt = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_iterationCount = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="PbeParameter"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The iteration count.</param>
        public PbeParameter(byte[] salt, int iterationCount)
        {
            m_salt = DerOctetString.FromContents(salt);
            m_iterationCount = DerInteger.ValueOf(iterationCount);
        }

        /// <summary>Return the salt.</summary>
        public byte[] GetSalt() => m_salt.GetOctets();

        /// <summary>Gets the iteration count.</summary>
        public BigInteger IterationCount => m_iterationCount.Value;

        /// <summary>Gets the iteration count object.</summary>
        public DerInteger IterationCountObject => m_iterationCount;

        /// <summary>Gets the salt.</summary>
        public Asn1OctetString Salt => m_salt;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_salt, m_iterationCount);
    }
}
