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
        public static Pbmac1Params GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Pbmac1Params pbmac1Params)
                return pbmac1Params;
            return new Pbmac1Params(Asn1Sequence.GetInstance(obj));
        }

        public static Pbmac1Params GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pbmac1Params(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Pbmac1Params GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pbmac1Params(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_keyDerivationFunc;
        private readonly AlgorithmIdentifier m_messageAuthScheme;

        private Pbmac1Params(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyDerivationFunc = AlgorithmIdentifier.GetInstance(seq[0]);
            m_messageAuthScheme = AlgorithmIdentifier.GetInstance(seq[1]);
        }

        public Pbmac1Params(AlgorithmIdentifier keyDerivationFunc, AlgorithmIdentifier messageAuthScheme)
        {
            m_keyDerivationFunc = keyDerivationFunc ?? throw new ArgumentNullException(nameof(keyDerivationFunc));
            m_messageAuthScheme = messageAuthScheme ?? throw new ArgumentNullException(nameof(messageAuthScheme));
        }

        public AlgorithmIdentifier KeyDerivationFunc => m_keyDerivationFunc;

        public AlgorithmIdentifier MessageAuthScheme => m_messageAuthScheme;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_keyDerivationFunc, m_messageAuthScheme);
    }
}
