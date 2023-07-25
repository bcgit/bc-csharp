using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of the EncryptionInfo element defined in RFC 4998:
     * <p/>
     * 1988 ASN.1 EncryptionInfo
     * <p/>
     * EncryptionInfo       ::=     SEQUENCE {
     * encryptionInfoType     OBJECT IDENTIFIER,
     * encryptionInfoValue    ANY DEFINED BY encryptionInfoType
     * }
     * <p/>
     * 1997-ASN.1 EncryptionInfo
     * <p/>
     * EncryptionInfo       ::=     SEQUENCE {
     * encryptionInfoType   ENCINFO-TYPE.&amp;id
     * ({SupportedEncryptionAlgorithms}),
     * encryptionInfoValue  ENCINFO-TYPE.&amp;Type
     * ({SupportedEncryptionAlgorithms}{&#064;encryptionInfoType})
     * }
     * <p/>
     * ENCINFO-TYPE ::= TYPE-IDENTIFIER
     * <p/>
     * SupportedEncryptionAlgorithms ENCINFO-TYPE ::= {...}
     */
    public class EncryptionInfo
        : Asn1Encodable
    {
        public static EncryptionInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptionInfo encryptionInfo)
                return encryptionInfo;
            return new EncryptionInfo(Asn1Sequence.GetInstance(obj));
        }

        public static EncryptionInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new EncryptionInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        /**
         * The OID for EncryptionInfo type.
         */
        private readonly DerObjectIdentifier m_encryptionInfoType;

        /**
         * The value of EncryptionInfo
         */
        private readonly Asn1Encodable m_encryptionInfoValue;

        private EncryptionInfo(Asn1Sequence sequence)
        {
            if (sequence.Count != 2)
                throw new ArgumentException("wrong sequence size in constructor: " + sequence.Count, nameof(sequence));

            m_encryptionInfoType = DerObjectIdentifier.GetInstance(sequence[0]);
            m_encryptionInfoValue = sequence[1];
        }

        public EncryptionInfo(DerObjectIdentifier encryptionInfoType, Asn1Encodable encryptionInfoValue)
        {
            m_encryptionInfoType = encryptionInfoType;
            m_encryptionInfoValue = encryptionInfoValue;
        }

        public virtual DerObjectIdentifier EncryptionInfoType => m_encryptionInfoType;

        public virtual Asn1Encodable EncryptionInfoValue => m_encryptionInfoValue;

        public override Asn1Object ToAsn1Object() => new DLSequence(m_encryptionInfoType, m_encryptionInfoValue);
    }
}
