using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class OriginatorPublicKey
        : Asn1Encodable
    {
        public static OriginatorPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OriginatorPublicKey originatorPublicKey)
                return originatorPublicKey;
            return new OriginatorPublicKey(Asn1Sequence.GetInstance(obj));
        }

        public static OriginatorPublicKey GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OriginatorPublicKey(Asn1Sequence.GetInstance(obj, explicitly));

        public static OriginatorPublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OriginatorPublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_algorithm;
        private readonly DerBitString m_publicKey;

        public OriginatorPublicKey(AlgorithmIdentifier algorithm, byte[] publicKey)
            : this(algorithm, new DerBitString(publicKey))
        {
        }

        public OriginatorPublicKey(AlgorithmIdentifier algorithm, DerBitString publicKey)
        {
            m_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            m_publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        private OriginatorPublicKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algorithm = AlgorithmIdentifier.GetInstance(seq[0]);
            m_publicKey = DerBitString.GetInstance(seq[1]);
        }

        public AlgorithmIdentifier Algorithm => m_algorithm;

        public DerBitString PublicKey => m_publicKey;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OriginatorPublicKey ::= Sequence {
         *     algorithm AlgorithmIdentifier,
         *     publicKey BIT STRING
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_algorithm, m_publicKey);
    }
}
