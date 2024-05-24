using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class Signature
        : Asn1Encodable
    {
        public static Signature GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Signature signature)
                return signature;
            return new Signature(Asn1Sequence.GetInstance(obj));
		}

        public static Signature GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new Signature(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signatureValue;
        private readonly Asn1Sequence m_certs;

        public Signature(AlgorithmIdentifier signatureAlgorithm, DerBitString signatureValue)
            : this(signatureAlgorithm, signatureValue, null)
        {
        }

        public Signature(AlgorithmIdentifier signatureAlgorithm, DerBitString signatureValue, Asn1Sequence certs)
        {
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_signatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
            m_certs = certs;
        }

        private Signature(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_signatureAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_signatureValue = DerBitString.GetInstance(seq[pos++]);
            m_certs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        public DerBitString SignatureValue => m_signatureValue;

        public byte[] GetSignatureOctets() => m_signatureValue.GetOctets();

        public Asn1Sequence Certs => m_certs;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * Signature       ::=     Sequence {
         *     signatureAlgorithm      AlgorithmIdentifier,
         *     signature               BIT STRING,
         *     certs               [0] EXPLICIT Sequence OF Certificate OPTIONAL}
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_signatureAlgorithm, m_signatureValue);
            v.AddOptionalTagged(true, 0, m_certs);
            return new DerSequence(v);
        }
    }
}
