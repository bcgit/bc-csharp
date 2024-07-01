using System;

using Org.BouncyCastle.Asn1.X509;

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
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_hashAlgorithm = AlgorithmIdentifier.GetInstance(seq[0]);
			m_hashedMessage = Asn1OctetString.GetInstance(seq[1]);
		}

		public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage)
		{
			m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
			m_hashedMessage = new DerOctetString(hashedMessage);
		}

		public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

		public Asn1OctetString HashedMessage => m_hashedMessage;

		public byte[] GetHashedMessage() => m_hashedMessage.GetOctets();

		/**
		 * <pre>
		 *    MessageImprint ::= SEQUENCE  {
		 *       hashAlgorithm                AlgorithmIdentifier,
		 *       hashedMessage                OCTET STRING  }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object() => new DerSequence(m_hashAlgorithm, m_hashedMessage);
	}
}
