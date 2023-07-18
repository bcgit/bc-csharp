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

		public static MessageImprint GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
            return new MessageImprint(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly byte[] m_hashedMessage;

        private MessageImprint(Asn1Sequence seq)
		{
			if (seq.Count != 2)
				throw new ArgumentException("Wrong number of elements in sequence", nameof(seq));

			m_hashAlgorithm = AlgorithmIdentifier.GetInstance(seq[0]);
			m_hashedMessage = Asn1OctetString.GetInstance(seq[1]).GetOctets();
		}

		public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage)
		{
			m_hashAlgorithm = hashAlgorithm;
			m_hashedMessage = hashedMessage;
		}

		public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

		public byte[] GetHashedMessage() => m_hashedMessage;

		/**
		 * <pre>
		 *    MessageImprint ::= SEQUENCE  {
		 *       hashAlgorithm                AlgorithmIdentifier,
		 *       hashedMessage                OCTET STRING  }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(m_hashAlgorithm, new DerOctetString(m_hashedMessage));
		}
	}
}
