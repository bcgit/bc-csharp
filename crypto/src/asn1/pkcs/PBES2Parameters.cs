using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class PbeS2Parameters
        : Asn1Encodable
    {
        public static PbeS2Parameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbeS2Parameters pbeS2Parameters)
                return pbeS2Parameters;
            return new PbeS2Parameters(Asn1Sequence.GetInstance(obj));
        }

        public static PbeS2Parameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeS2Parameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PbeS2Parameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeS2Parameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly KeyDerivationFunc m_func;
        private readonly EncryptionScheme m_scheme;

        private PbeS2Parameters(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            AlgorithmIdentifier func = AlgorithmIdentifier.GetInstance(seq[0]);
            m_func = new KeyDerivationFunc(func.Algorithm, func.Parameters);

            m_scheme = EncryptionScheme.GetInstance(seq[1]);
        }

        public PbeS2Parameters(KeyDerivationFunc keyDevFunc, EncryptionScheme encScheme)
        {
            m_func = keyDevFunc ?? throw new ArgumentNullException(nameof(keyDevFunc));
            m_scheme = encScheme ?? throw new ArgumentNullException(nameof(encScheme));
        }

        public KeyDerivationFunc KeyDerivationFunc => m_func;

        public EncryptionScheme EncryptionScheme => m_scheme;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_func, m_scheme);
    }
}
