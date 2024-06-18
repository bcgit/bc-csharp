using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class RecipientInfo
        : Asn1Encodable, IAsn1Choice
    {
        public static RecipientInfo GetInstance(object o)
        {
            if (o == null)
                return null;

            if (o is RecipientInfo recipientInfo)
                return recipientInfo;

            if (o is Asn1Sequence sequence)
                return new RecipientInfo(sequence);

            if (o is Asn1TaggedObject taggedObject)
                return new RecipientInfo(taggedObject);

            throw new ArgumentException("unknown object in factory: " + Platform.GetTypeName(o), nameof(o));
        }

        public static RecipientInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(taggedObject, declaredExplicit, GetInstance);
        }

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

        private KekRecipientInfo GetKekInfo(Asn1TaggedObject tagged)
        {
            // For compatibility with erroneous version, we don't always pass 'false' here
            bool declaredExplicit = tagged.IsExplicit();

            return KekRecipientInfo.GetInstance(tagged, declaredExplicit);
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
    }
}
