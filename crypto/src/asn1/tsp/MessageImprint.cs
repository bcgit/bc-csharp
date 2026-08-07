using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Tsp
{
    public class MessageImprint
        : Asn1Encodable
    {
        public static MessageImprint GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MessageImprint messageImprint)
                return messageImprint;
            return new MessageImprint(Asn1Sequence.GetInstance(obj));
        }

        public static MessageImprint GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MessageImprint(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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

        public MessageImprint(AlgorithmIdentifier hashAlgorithm, Asn1OctetString hashedMessage)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_hashedMessage = hashedMessage ?? throw new ArgumentNullException(nameof(hashedMessage));
        }

        public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_hashedMessage = DerOctetString.FromContents(hashedMessage);
        }

        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        public Asn1OctetString HashedMessage => m_hashedMessage;

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
