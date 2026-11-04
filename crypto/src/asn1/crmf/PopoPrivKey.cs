using System;

using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The POPOPrivKey choice of RFC 4211: proof of possession of a private key.</summary>
    public class PopoPrivKey
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>The <c>thisMessage</c> constant, with the value <c>0</c>.</summary>
        public const int thisMessage = 0;
        /// <summary>The <c>subsequentMessage</c> constant, with the value <c>1</c>.</summary>
        public const int subsequentMessage = 1;
        /// <summary>The <c>dhMAC</c> constant, with the value <c>2</c>.</summary>
        public const int dhMAC = 2;
        /// <summary>The <c>agreeMAC</c> constant, with the value <c>3</c>.</summary>
        public const int agreeMAC = 3;
        /// <summary>The <c>encryptedKey</c> constant, with the value <c>4</c>.</summary>
        public const int encryptedKey = 4;

        /// <summary>Return an <see cref="PopoPrivKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PopoPrivKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PopoPrivKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PopoPrivKey GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="PopoPrivKey"/> from a tagged object.</summary>
        /// <param name="tagged">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoPrivKey"/>.</returns>
        public static PopoPrivKey GetInstance(Asn1TaggedObject tagged, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(tagged, isExplicit, GetInstance);

        /// <summary>Return an <see cref="PopoPrivKey"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="PopoPrivKey"/>, or null if <paramref name="element"/> is null.</returns>
        public static PopoPrivKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PopoPrivKey popoPrivKey)
                return popoPrivKey;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new PopoPrivKey(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        /// <summary>Return an <see cref="PopoPrivKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoPrivKey"/>.</returns>
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
                    return DerBitString.GetTagged(taggedObject, false);
                case subsequentMessage:
                    return SubsequentMessage.ValueOf(DerInteger.GetTagged(taggedObject, false).IntValueExact);
                case agreeMAC:
                    return PKMacValue.GetTagged(taggedObject, false);
                case encryptedKey:
                    return EnvelopedData.GetTagged(taggedObject, false);

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

        /// <summary>Create a new <see cref="PopoPrivKey"/>.</summary>
        /// <param name="pkMacValue">The pk mac value.</param>
        public PopoPrivKey(PKMacValue pkMacValue)
            : this(agreeMAC, pkMacValue)
        {
        }

        /// <summary>Create a new <see cref="PopoPrivKey"/>.</summary>
        /// <param name="msg">The message.</param>
        public PopoPrivKey(SubsequentMessage msg)
            : this(subsequentMessage, msg)
        {
        }

        /// <summary>Gets the type.</summary>
        public virtual int Type => m_tagNo;

        /// <summary>Gets the value.</summary>
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
