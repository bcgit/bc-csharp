using System;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class ProofOfPossession
        : Asn1Encodable, IAsn1Choice
    {
        public const int TYPE_RA_VERIFIED = 0;
        public const int TYPE_SIGNING_KEY = 1;
        public const int TYPE_KEY_ENCIPHERMENT = 2;
        public const int TYPE_KEY_AGREEMENT = 3;

        public static ProofOfPossession GetInstance(object obj)
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

        public static ProofOfPossession GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static ProofOfPossession GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is ProofOfPossession proofOfPossession)
                return proofOfPossession;

            if (element is Asn1TaggedObject taggedObject)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new ProofOfPossession(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        public static ProofOfPossession GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case 0:
                    return DerNull.GetInstance(taggedObject, false);
                case 1:
                    return PopoSigningKey.GetInstance(taggedObject, false);
                case 2:
                case 3:
                    // CHOICE so explicit
                    return PopoPrivKey.GetInstance(taggedObject, true);
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

        public virtual int Type => m_tagNo;

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
