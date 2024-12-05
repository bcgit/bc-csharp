using System;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class EncKeyWithID
        : Asn1Encodable
    {
        public static EncKeyWithID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncKeyWithID encKeyWithID)
                return encKeyWithID;
            return new EncKeyWithID(Asn1Sequence.GetInstance(obj));
        }

        public static EncKeyWithID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncKeyWithID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static EncKeyWithID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncKeyWithID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private static Asn1Encodable GetOptionalChoice(Asn1Encodable element)
        {
            var _string = DerUtf8String.GetOptional(element);
            if (_string != null)
                return _string;

            return GeneralName.GetInstance(element);
        }

        private readonly PrivateKeyInfo m_privKeyInfo;
        private readonly Asn1Encodable m_identifier;

        private EncKeyWithID(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_privKeyInfo = PrivateKeyInfo.GetInstance(seq[0]);

            if (count > 1)
            {
                m_identifier = GetOptionalChoice(seq[1]);
            }
        }

        private EncKeyWithID(PrivateKeyInfo privKeyInfo, Asn1Encodable identifier)
        {
            m_privKeyInfo = privKeyInfo ?? throw new ArgumentNullException(nameof(privKeyInfo));
            m_identifier = identifier;
        }

        public EncKeyWithID(PrivateKeyInfo privKeyInfo)
            : this(privKeyInfo, (Asn1Encodable)null)
        {
        }

        public EncKeyWithID(PrivateKeyInfo privKeyInfo, DerUtf8String str)
            : this(privKeyInfo, (Asn1Encodable)str)
        {
        }

        public EncKeyWithID(PrivateKeyInfo privKeyInfo, GeneralName generalName)
            : this(privKeyInfo, (Asn1Encodable)generalName)
        {
        }

        public virtual PrivateKeyInfo PrivateKey => m_privKeyInfo;

        public virtual bool HasIdentifier => m_identifier != null;

        public virtual bool IsIdentifierUtf8String => m_identifier is DerUtf8String;

        public virtual Asn1Encodable Identifier => m_identifier;

        /**
         * <pre>
         * EncKeyWithID ::= SEQUENCE {
         *      privateKey           PrivateKeyInfo,
         *      identifier CHOICE {
         *         string               UTF8String,
         *         generalName          GeneralName
         *     } OPTIONAL
         * }
         * </pre>
         * @return
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_identifier == null
                ?  new DerSequence(m_privKeyInfo)
                :  new DerSequence(m_privKeyInfo, m_identifier);
        }
    }
}
