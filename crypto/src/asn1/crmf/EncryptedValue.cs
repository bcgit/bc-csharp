using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class EncryptedValue
        : Asn1Encodable
    {
        public static EncryptedValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedValue encryptedValue)
                return encryptedValue;
            return new EncryptedValue(Asn1Sequence.GetInstance(obj));
        }

        public static EncryptedValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new EncryptedValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly AlgorithmIdentifier m_intendedAlg;
        private readonly AlgorithmIdentifier m_symmAlg;
        private readonly DerBitString m_encSymmKey;
        private readonly AlgorithmIdentifier m_keyAlg;
        private readonly Asn1OctetString m_valueHint;
        private readonly DerBitString m_encValue;

        private EncryptedValue(Asn1Sequence seq)
        {
            int index = 0;
            while (seq[index] is Asn1TaggedObject tObj)
            {
                switch (tObj.TagNo)
                {
                case 0:
                    m_intendedAlg = AlgorithmIdentifier.GetInstance(tObj, false);
                    break;
                case 1:
                    m_symmAlg = AlgorithmIdentifier.GetInstance(tObj, false);
                    break;
                case 2:
                    m_encSymmKey = DerBitString.GetInstance(tObj, false);
                    break;
                case 3:
                    m_keyAlg = AlgorithmIdentifier.GetInstance(tObj, false);
                    break;
                case 4:
                    m_valueHint = Asn1OctetString.GetInstance(tObj, false);
                    break;
                }
                ++index;
            }

            m_encValue = DerBitString.GetInstance(seq[index]);
        }

        public EncryptedValue(AlgorithmIdentifier intendedAlg, AlgorithmIdentifier symmAlg, DerBitString encSymmKey,
            AlgorithmIdentifier keyAlg, Asn1OctetString valueHint, DerBitString encValue)
        {
            if (encValue == null)
                throw new ArgumentNullException(nameof(encValue));

            m_intendedAlg = intendedAlg;
            m_symmAlg = symmAlg;
            m_encSymmKey = encSymmKey;
            m_keyAlg = keyAlg;
            m_valueHint = valueHint;
            m_encValue = encValue;
        }

        public virtual AlgorithmIdentifier IntendedAlg => m_intendedAlg;

        public virtual AlgorithmIdentifier SymmAlg => m_symmAlg;

        public virtual DerBitString EncSymmKey => m_encSymmKey;

        public virtual AlgorithmIdentifier KeyAlg => m_keyAlg;

        public virtual Asn1OctetString ValueHint => m_valueHint;

        public virtual DerBitString EncValue => m_encValue;

        /**
         * <pre>
         * (IMPLICIT TAGS)
         * EncryptedValue ::= SEQUENCE {
         *                     intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
         *                     -- the intended algorithm for which the value will be used
         *                     symmAlg       [1] AlgorithmIdentifier  OPTIONAL,
         *                     -- the symmetric algorithm used to encrypt the value
         *                     encSymmKey    [2] BIT STRING           OPTIONAL,
         *                     -- the (encrypted) symmetric key used to encrypt the value
         *                     keyAlg        [3] AlgorithmIdentifier  OPTIONAL,
         *                     -- algorithm used to encrypt the symmetric key
         *                     valueHint     [4] OCTET STRING         OPTIONAL,
         *                     -- a brief description or identifier of the encValue content
         *                     -- (may be meaningful only to the sending entity, and used only
         *                     -- if EncryptedValue might be re-examined by the sending entity
         *                     -- in the future)
         *                     encValue       BIT STRING }
         *                     -- the encrypted value itself
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(6);
            v.AddOptionalTagged(false, 0, m_intendedAlg);
            v.AddOptionalTagged(false, 1, m_symmAlg);
            v.AddOptionalTagged(false, 2, m_encSymmKey);
            v.AddOptionalTagged(false, 3, m_keyAlg);
            v.AddOptionalTagged(false, 4, m_valueHint);
            v.Add(m_encValue);
            return new DerSequence(v);
        }
    }
}
