using System;

namespace Org.BouncyCastle.Asn1.Misc
{
    /// <summary>RFC 7914 scrypt parameters.</summary>
    /// <remarks>
    /// <code>
    /// scrypt-params ::= SEQUENCE {
    ///     salt                        OCTET STRING,
    ///     costParameter               INTEGER (1..MAX),
    ///     blockSize                   INTEGER (1..MAX),
    ///     parallelizationParameter    INTEGER (1..MAX),
    ///     keyLength                   INTEGER (1..MAX) OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public sealed class ScryptParams
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ScryptParams"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ScryptParams"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ScryptParams"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ScryptParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ScryptParams scryptParams)
                return scryptParams;
            return new ScryptParams(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ScryptParams"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ScryptParams"/>.</returns>
        public static ScryptParams GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ScryptParams(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ScryptParams"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ScryptParams"/>.</returns>
        public static ScryptParams GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ScryptParams(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_salt;
        private readonly DerInteger m_costParameter;
        private readonly DerInteger m_blockSize;
        private readonly DerInteger m_parallelizationParameter;
        private readonly DerInteger m_keyLength;

        /// <summary>Create a new <see cref="ScryptParams"/>.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="costParameter">The cost parameter.</param>
        /// <param name="blockSize">The block size in bytes.</param>
        /// <param name="parallelizationParameter">The parallelization parameter.</param>
        /// <param name="keyLength">The key length.</param>
        public ScryptParams(Asn1OctetString salt, DerInteger costParameter, DerInteger blockSize,
            DerInteger parallelizationParameter, DerInteger keyLength)
        {
            m_salt = salt ?? throw new ArgumentNullException(nameof(salt));
            m_costParameter = costParameter ?? throw new ArgumentNullException(nameof(costParameter));
            m_blockSize = blockSize ?? throw new ArgumentNullException(nameof(blockSize));
            m_parallelizationParameter = parallelizationParameter
                ?? throw new ArgumentNullException(nameof(parallelizationParameter));
            m_keyLength = keyLength;
        }

        private ScryptParams(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_salt = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_costParameter = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_blockSize = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_parallelizationParameter = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_keyLength = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the block size.</summary>
        public DerInteger BlockSize => m_blockSize;

        /// <summary>Gets the cost parameter.</summary>
        public DerInteger CostParameter => m_costParameter;

        /// <summary>Gets the key length.</summary>
        public DerInteger KeyLength => m_keyLength;

        /// <summary>Gets the parallelization parameter.</summary>
        public DerInteger ParallelizationParameter => m_parallelizationParameter;

        /// <summary>Gets the salt.</summary>
        public Asn1OctetString Salt => m_salt;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_salt, m_costParameter, m_blockSize, m_parallelizationParameter);
            v.AddOptional(m_keyLength);
            return new DerSequence(v);
        }
    }
}
