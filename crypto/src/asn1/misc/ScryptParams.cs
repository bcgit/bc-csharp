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
        public static ScryptParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ScryptParams scryptParams)
                return scryptParams;
            return new ScryptParams(Asn1Sequence.GetInstance(obj));
        }

        public static ScryptParams GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ScryptParams(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ScryptParams GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ScryptParams(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_salt;
        private readonly DerInteger m_costParameter;
        private readonly DerInteger m_blockSize;
        private readonly DerInteger m_parallelizationParameter;
        private readonly DerInteger m_keyLength;

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

        public DerInteger BlockSize => m_blockSize;

        public DerInteger CostParameter => m_costParameter;

        public DerInteger KeyLength => m_keyLength;

        public DerInteger ParallelizationParameter => m_parallelizationParameter;

        public Asn1OctetString Salt => m_salt;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_salt, m_costParameter, m_blockSize, m_parallelizationParameter);
            v.AddOptional(m_keyLength);
            return new DerSequence(v);
        }
    }
}
