using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The ProofOfPossession choice of RFC 4211.</summary>
    public class ProofOfPossession
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>The <c>TYPE_RA_VERIFIED</c> constant, with the value <c>0</c>.</summary>
        public const int TYPE_RA_VERIFIED = 0;
        /// <summary>The <c>TYPE_SIGNING_KEY</c> constant, with the value <c>1</c>.</summary>
        public const int TYPE_SIGNING_KEY = 1;
        /// <summary>The <c>TYPE_KEY_ENCIPHERMENT</c> constant, with the value <c>2</c>.</summary>
        public const int TYPE_KEY_ENCIPHERMENT = 2;
        /// <summary>The <c>TYPE_KEY_AGREEMENT</c> constant, with the value <c>3</c>.</summary>
        public const int TYPE_KEY_AGREEMENT = 3;

        /// <summary>Return an <see cref="ProofOfPossession"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ProofOfPossession"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ProofOfPossession"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ProofOfPossession GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="ProofOfPossession"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ProofOfPossession"/>.</returns>
        public static ProofOfPossession GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="ProofOfPossession"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="ProofOfPossession"/>, or null if <paramref name="element"/> is null.</returns>
        public static ProofOfPossession GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is ProofOfPossession proofOfPossession)
                return proofOfPossession;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new ProofOfPossession(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        /// <summary>Return an <see cref="ProofOfPossession"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ProofOfPossession"/>.</returns>
        public static ProofOfPossession GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case 0:
                    return Asn1Null.GetTagged(taggedObject, false);
                case 1:
                    return PopoSigningKey.GetTagged(taggedObject, false);
                case 2:
                case 3:
                    // CHOICE so explicit
                    return PopoPrivKey.GetTagged(taggedObject, true);
                }
            }
            return null;
        }

        private readonly int m_tagNo;
        private readonly Asn1Encodable m_obj;

        private ProofOfPossession(int tagNo, Asn1Encodable obj)
        {
            m_tagNo = tagNo;
            m_obj = obj ?? throw new ArgumentNullException(nameof(obj));
        }

        /** Creates a ProofOfPossession with type raVerified. */
        public ProofOfPossession()
            : this(TYPE_RA_VERIFIED, DerNull.Instance)
        {
        }

        /** Creates a ProofOfPossession for a signing key. */
        public ProofOfPossession(PopoSigningKey Poposk)
            : this(TYPE_SIGNING_KEY, Poposk)
        {
        }

        /**
         * Creates a ProofOfPossession for key encipherment or agreement.
         * @param type one of TYPE_KEY_ENCIPHERMENT or TYPE_KEY_AGREEMENT
         */
        public ProofOfPossession(int type, PopoPrivKey privkey)
            : this(type, (Asn1Encodable)privkey)
        {
        }

        /// <summary>Gets the type.</summary>
        public virtual int Type => m_tagNo;

        /// <summary>Gets the object.</summary>
        public virtual Asn1Encodable Object => m_obj;

        /**
         * <pre>
         * ProofOfPossession ::= CHOICE {
         *                           raVerified        [0] NULL,
         *                           -- used if the RA has already verified that the requester is in
         *                           -- possession of the private key
         *                           signature         [1] PopoSigningKey,
         *                           keyEncipherment   [2] PopoPrivKey,
         *                           keyAgreement      [3] PopoPrivKey }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            // NOTE: Explicit tagging automatically applied for PopoPrivKey (a CHOICE)
            return new DerTaggedObject(false, m_tagNo, m_obj);
        }
    }
}
