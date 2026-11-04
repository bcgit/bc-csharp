using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /// <summary>The MessageImprint structure of RFC 3161: a hash algorithm and a hash value.</summary>
    public class MessageImprint
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="MessageImprint"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="MessageImprint"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="MessageImprint"/>, or null if <paramref name="obj"/> is null.</returns>
        public static MessageImprint GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MessageImprint messageImprint)
                return messageImprint;
            return new MessageImprint(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="MessageImprint"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MessageImprint"/>.</returns>
        public static MessageImprint GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MessageImprint(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="MessageImprint"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MessageImprint"/>.</returns>
        public static MessageImprint GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MessageImprint(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly Asn1OctetString m_hashedMessage;

        private MessageImprint(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_hashedMessage = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="MessageImprint"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="hashedMessage">The hashed message.</param>
        public MessageImprint(AlgorithmIdentifier hashAlgorithm, Asn1OctetString hashedMessage)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_hashedMessage = hashedMessage ?? throw new ArgumentNullException(nameof(hashedMessage));
        }

        /// <summary>Create a new <see cref="MessageImprint"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="hashedMessage">The hashed message.</param>
        public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_hashedMessage = DerOctetString.FromContents(hashedMessage);
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Gets the hashed message.</summary>
        public Asn1OctetString HashedMessage => m_hashedMessage;

        /// <summary>Return the hashed message.</summary>
        public byte[] GetHashedMessage() => Arrays.Clone(m_hashedMessage.GetOctets());

        /// <remarks>
        /// <code>
        /// MessageImprint::= SEQUENCE {
        ///     hashAlgorithm   AlgorithmIdentifier,
        ///     hashedMessage   OCTET STRING
        /// }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_hashAlgorithm, m_hashedMessage);
    }
}
