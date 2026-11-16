using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     * From https://datatracker.ietf.org/doc/html/rfc8018
     *
     * <pre>
     * PBMAC1-params ::= SEQUENCE {
     *     keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
     *     messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}} }
     * </pre>
     */
    public sealed class Pbmac1Params
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Pbmac1Params"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Pbmac1Params"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Pbmac1Params"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Pbmac1Params GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Pbmac1Params pbmac1Params)
                return pbmac1Params;
            return new Pbmac1Params(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Pbmac1Params"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Pbmac1Params"/>.</returns>
        public static Pbmac1Params GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pbmac1Params(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Pbmac1Params"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Pbmac1Params"/>.</returns>
        public static Pbmac1Params GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pbmac1Params(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_keyDerivationFunc;
        private readonly AlgorithmIdentifier m_messageAuthScheme;

        private Pbmac1Params(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyDerivationFunc = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_messageAuthScheme = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Pbmac1Params"/>.</summary>
        /// <param name="keyDerivationFunc">The key derivation func.</param>
        /// <param name="messageAuthScheme">The message auth scheme.</param>
        public Pbmac1Params(AlgorithmIdentifier keyDerivationFunc, AlgorithmIdentifier messageAuthScheme)
        {
            m_keyDerivationFunc = keyDerivationFunc ?? throw new ArgumentNullException(nameof(keyDerivationFunc));
            m_messageAuthScheme = messageAuthScheme ?? throw new ArgumentNullException(nameof(messageAuthScheme));
        }

        /// <summary>Gets the key derivation func.</summary>
        public AlgorithmIdentifier KeyDerivationFunc => m_keyDerivationFunc;

        /// <summary>Gets the message auth scheme.</summary>
        public AlgorithmIdentifier MessageAuthScheme => m_messageAuthScheme;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_keyDerivationFunc, m_messageAuthScheme);
    }
}
