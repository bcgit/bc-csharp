using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     *  KemBMParameter ::= SEQUENCE {
     *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
     *      len              INTEGER (1..MAX),
     *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *   }
     * </pre>
     */
    public class KemBMParameter
        : Asn1Encodable
    {
        public static KemBMParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KemBMParameter kemBMParameter)
                return kemBMParameter;
            return new KemBMParameter(Asn1Sequence.GetInstance(obj));
        }

        public static KemBMParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemBMParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_kdf;
        private readonly DerInteger m_len;
        private readonly AlgorithmIdentifier m_mac;

        private KemBMParameter(Asn1Sequence seq)
        {
            if (seq.Count != 3)
                throw new ArgumentException("sequence size should 3", nameof(seq));

            m_kdf = AlgorithmIdentifier.GetInstance(seq[0]);
            m_len = DerInteger.GetInstance(seq[1]);
            m_mac = AlgorithmIdentifier.GetInstance(seq[2]);
        }

        public KemBMParameter(AlgorithmIdentifier kdf, DerInteger len, AlgorithmIdentifier mac)
        {
            m_kdf = kdf;
            m_len = len;
            m_mac = mac;
        }

        public KemBMParameter(AlgorithmIdentifier kdf, long len, AlgorithmIdentifier mac)
            : this(kdf, new DerInteger(len), mac)
        {
        }

        public virtual AlgorithmIdentifier Kdf => m_kdf;

        public virtual DerInteger Len => m_len;

        public virtual AlgorithmIdentifier Mac => m_mac;

        /**
         * <pre>
         *  KemBMParameter ::= SEQUENCE {
         *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
         *      len              INTEGER (1..MAX),
         *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
         *    }
         * </pre>
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_kdf, m_len, m_mac);
    }
}
