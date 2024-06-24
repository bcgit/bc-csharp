using System;

using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class PopoPrivKey
        : Asn1Encodable, IAsn1Choice
    {
        public const int thisMessage = 0;
        public const int subsequentMessage = 1;
        public const int dhMAC = 2;
        public const int agreeMAC = 3;
        public const int encryptedKey = 4;

        public static PopoPrivKey GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is Asn1Encodable element)
            {
                var result = GetOptional(element);
                if (result != null)
                    return result;
            }

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

        public static PopoPrivKey GetInstance(Asn1TaggedObject tagged, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(tagged, isExplicit, GetInstance);

        public static PopoPrivKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PopoPrivKey popoPrivKey)
                return popoPrivKey;

            if (element is Asn1TaggedObject taggedObject)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new PopoPrivKey(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        public static PopoPrivKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case thisMessage:
                case dhMAC:
                    return DerBitString.GetInstance(taggedObject, false);
                case subsequentMessage:
                    return SubsequentMessage.ValueOf(DerInteger.GetInstance(taggedObject, false).IntValueExact);
                case agreeMAC:
                    return PKMacValue.GetInstance(taggedObject, false);
                case encryptedKey:
                    return EnvelopedData.GetInstance(taggedObject, false);

                }
            }
            return null;
        }

        private readonly int m_tagNo;
        private readonly Asn1Encodable m_obj;

        private PopoPrivKey(int tagNo, Asn1Encodable obj)
        {
            m_tagNo = tagNo;
            m_obj = obj ?? throw new ArgumentNullException(nameof(obj));
        }

        public PopoPrivKey(PKMacValue pkMacValue)
            : this(agreeMAC, pkMacValue)
        {
        }

        public PopoPrivKey(SubsequentMessage msg)
            : this(subsequentMessage, msg)
        {
        }

        public virtual int Type => m_tagNo;

        public virtual Asn1Encodable Value => m_obj;

        /**
         * <pre>
         * PopoPrivKey ::= CHOICE {
         *        thisMessage       [0] BIT STRING,         -- Deprecated
         *         -- possession is proven in this message (which contains the private
         *         -- key itself (encrypted for the CA))
         *        subsequentMessage [1] SubsequentMessage,
         *         -- possession will be proven in a subsequent message
         *        dhMAC             [2] BIT STRING,         -- Deprecated
         *        agreeMAC          [3] PKMACValue,
         *        encryptedKey      [4] EnvelopedData }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerTaggedObject(false, m_tagNo, m_obj);
    }
}
