using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * DHBMParameter ::= SEQUENCE {
     * owf                 AlgorithmIdentifier,
     * -- AlgId for a One-Way Function (SHA-1 recommended)
     * mac                 AlgorithmIdentifier
     * -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     * }   -- or HMAC [RFC2104, RFC2202])
     */
    public class DhbmParameter
        : Asn1Encodable
    {
        public static DhbmParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DhbmParameter dhbmParameter)
                return dhbmParameter;
            return new DhbmParameter(Asn1Sequence.GetInstance(obj));
        }

        public static DhbmParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new DhbmParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly AlgorithmIdentifier m_owf;
        private readonly AlgorithmIdentifier m_mac;

        private DhbmParameter(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_owf = AlgorithmIdentifier.GetInstance(seq[0]);
            m_mac = AlgorithmIdentifier.GetInstance(seq[1]);
        }

        public DhbmParameter(AlgorithmIdentifier owf, AlgorithmIdentifier mac)
        {
            m_owf = owf ?? throw new ArgumentNullException(nameof(owf));
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        public virtual AlgorithmIdentifier Owf => m_owf;

        public virtual AlgorithmIdentifier Mac => m_mac;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_owf, m_mac);
    }
}
