using System;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    public class Gost3410PublicKeyAlgParameters
        : Asn1Encodable
    {
        public static Gost3410PublicKeyAlgParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Gost3410PublicKeyAlgParameters gost3410PublicKeyAlgParameters)
                return gost3410PublicKeyAlgParameters;
            return new Gost3410PublicKeyAlgParameters(Asn1Sequence.GetInstance(obj));
        }

        public static Gost3410PublicKeyAlgParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost3410PublicKeyAlgParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Gost3410PublicKeyAlgParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost3410PublicKeyAlgParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_publicKeyParamSet;
        private readonly DerObjectIdentifier m_digestParamSet;
        private readonly DerObjectIdentifier m_encryptionParamSet;

        private Gost3410PublicKeyAlgParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_publicKeyParamSet = DerObjectIdentifier.GetInstance(seq[pos++]);
            m_digestParamSet = DerObjectIdentifier.GetInstance(seq[pos++]);
            m_encryptionParamSet = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Gost3410PublicKeyAlgParameters(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet)
            : this(publicKeyParamSet, digestParamSet, null)
        {
        }

        public Gost3410PublicKeyAlgParameters(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet,
            DerObjectIdentifier encryptionParamSet)
        {
            m_publicKeyParamSet = publicKeyParamSet ?? throw new ArgumentNullException(nameof(publicKeyParamSet));
            m_digestParamSet = digestParamSet ?? throw new ArgumentNullException(nameof(digestParamSet));
            m_encryptionParamSet = encryptionParamSet;
        }

        public DerObjectIdentifier PublicKeyParamSet => m_publicKeyParamSet;

		public DerObjectIdentifier DigestParamSet => m_digestParamSet;

		public DerObjectIdentifier EncryptionParamSet => m_encryptionParamSet;

		public override Asn1Object ToAsn1Object()
        {
            return m_encryptionParamSet == null
                ?  new DerSequence(m_publicKeyParamSet, m_digestParamSet)
                :  new DerSequence(m_publicKeyParamSet, m_digestParamSet, m_encryptionParamSet);
        }
    }
}
