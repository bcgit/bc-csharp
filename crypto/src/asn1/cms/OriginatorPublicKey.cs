using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The OriginatorPublicKey structure of RFC 5652.</summary>
    public class OriginatorPublicKey
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OriginatorPublicKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OriginatorPublicKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OriginatorPublicKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OriginatorPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OriginatorPublicKey originatorPublicKey)
                return originatorPublicKey;
            return new OriginatorPublicKey(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OriginatorPublicKey"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OriginatorPublicKey"/>.</returns>
        public static OriginatorPublicKey GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OriginatorPublicKey(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="OriginatorPublicKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OriginatorPublicKey"/>.</returns>
        public static OriginatorPublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OriginatorPublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_algorithm;
        private readonly DerBitString m_publicKey;

        /// <summary>Create a new <see cref="OriginatorPublicKey"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="publicKey">The public key.</param>
        public OriginatorPublicKey(AlgorithmIdentifier algorithm, byte[] publicKey)
            : this(algorithm, new DerBitString(publicKey))
        {
        }

        /// <summary>Create a new <see cref="OriginatorPublicKey"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="publicKey">The public key.</param>
        public OriginatorPublicKey(AlgorithmIdentifier algorithm, DerBitString publicKey)
        {
            m_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            m_publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        private OriginatorPublicKey(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_publicKey = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the algorithm.</summary>
        public AlgorithmIdentifier Algorithm => m_algorithm;

        /// <summary>Gets the public key.</summary>
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
