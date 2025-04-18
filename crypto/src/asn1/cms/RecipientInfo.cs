using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class RecipientInfo
        : Asn1Encodable, IAsn1Choice
    {
        // TODO[api] Rename 'o' to 'obj'
        public static RecipientInfo GetInstance(object o) => Asn1Utilities.GetInstanceChoice(o, GetOptional);

        public static RecipientInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static RecipientInfo GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is RecipientInfo recipientInfo)
                return recipientInfo;

            KeyTransRecipientInfo ktri = KeyTransRecipientInfo.GetOptional(element);
            if (ktri != null)
                return new RecipientInfo(ktri);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(1))
                    return new RecipientInfo(KeyAgreeRecipientInfo.GetTagged(taggedObject, false));

                if (taggedObject.HasContextTag(2))
                    return new RecipientInfo(GetKekInfo(taggedObject));

                if (taggedObject.HasContextTag(3))
                    return new RecipientInfo(PasswordRecipientInfo.GetTagged(taggedObject, false));

                if (taggedObject.HasContextTag(4))
                    return new RecipientInfo(OtherRecipientInfo.GetTagged(taggedObject, false));
            }

            return null;
        }

        public static RecipientInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_info;

        public RecipientInfo(KeyTransRecipientInfo info)
        {
            m_info = info ?? throw new ArgumentNullException(nameof(info));
        }

        public RecipientInfo(KeyAgreeRecipientInfo info)
        {
            m_info = new DerTaggedObject(false, 1, info);
        }

        public RecipientInfo(KekRecipientInfo info)
        {
            m_info = new DerTaggedObject(false, 2, info);
        }

        public RecipientInfo(PasswordRecipientInfo info)
        {
            m_info = new DerTaggedObject(false, 3, info);
        }

        public RecipientInfo(OtherRecipientInfo info)
        {
            m_info = new DerTaggedObject(false, 4, info);
        }

        [Obsolete("Will be removed")]
        public RecipientInfo(Asn1Object info)
        {
            m_info = info ?? throw new ArgumentNullException(nameof(info));
        }

        [Obsolete("Will be removed")]
        public DerInteger Version
        {
            get
            {
                if (!(m_info is Asn1TaggedObject tagged))
                    return KeyTransRecipientInfo.GetInstance(m_info).Version;

                if (tagged.HasContextTag())
                {
                    switch (tagged.TagNo)
                    {
                    case 1:
                        return KeyAgreeRecipientInfo.GetInstance(tagged, false).Version;
                    case 2:
                        return GetKekInfo(tagged).Version;
                    case 3:
                        return PasswordRecipientInfo.GetInstance(tagged, false).Version;
                    case 4:
                        return DerInteger.Zero;    // no syntax version for OtherRecipientInfo
                    }
                }
                throw new InvalidOperationException("unknown tag");
            }
        }

        public bool IsTagged => m_info is Asn1TaggedObject;

        public Asn1Encodable Info
        {
            get
            {
                if (!(m_info is Asn1TaggedObject tagged))
                    return KeyTransRecipientInfo.GetInstance(m_info);

                if (tagged.HasContextTag())
                {
                    switch (tagged.TagNo)
                    {
                    case 1:
                        return KeyAgreeRecipientInfo.GetInstance(tagged, false);
                    case 2:
                        return GetKekInfo(tagged);
                    case 3:
                        return PasswordRecipientInfo.GetInstance(tagged, false);
                    case 4:
                        return OtherRecipientInfo.GetInstance(tagged, false);
                    }
                }
                throw new InvalidOperationException("unknown tag");
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * RecipientInfo ::= CHOICE {
         *     ktri KeyTransRecipientInfo,
         *     kari [1] KeyAgreeRecipientInfo,
         *     kekri [2] KekRecipientInfo,
         *     pwri [3] PasswordRecipientInfo,
         *     ori [4] OtherRecipientInfo }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_info.ToAsn1Object();

        internal bool IsKeyTransV0()
        {
            if (m_info is Asn1TaggedObject)
                return false;

            var ktri = KeyTransRecipientInfo.GetInstance(m_info);

            return ktri.Version.HasValue(0);
        }

        internal bool IsPasswordOrOther()
        {
            if (m_info is Asn1TaggedObject tagged && tagged.HasContextTag())
            {
                switch (tagged.TagNo)
                {
                case 3:
                case 4:
                    return true;
                }
            }
            return false;
        }

        // TODO[api] Consider whether to continue supporting this
        private static KekRecipientInfo GetKekInfo(Asn1TaggedObject tagged)
        {
            Debug.Assert(tagged.HasContextTag(2));

            // For compatibility with erroneous version, we don't always pass 'false' here
            bool declaredExplicit = tagged.IsExplicit();

            return KekRecipientInfo.GetTagged(tagged, declaredExplicit);
        }
    }
}
