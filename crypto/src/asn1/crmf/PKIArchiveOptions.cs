using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class PkiArchiveOptions
        : Asn1Encodable, IAsn1Choice
    {
        public const int encryptedPrivKey = 0;
        public const int keyGenParameters = 1;
        public const int archiveRemGenPrivKey = 2;

        public static PkiArchiveOptions GetInstance(object obj)
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

        public static PkiArchiveOptions GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static PkiArchiveOptions GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PkiArchiveOptions pkiArchiveOptions)
                return pkiArchiveOptions;

            if (element is Asn1TaggedObject taggedObject)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new PkiArchiveOptions(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        public static PkiArchiveOptions GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case encryptedPrivKey:
                    // CHOICE so explicit
                    return EncryptedKey.GetInstance(taggedObject, true);
                case keyGenParameters:
                    return Asn1OctetString.GetInstance(taggedObject, false);
                case archiveRemGenPrivKey:
                    return DerBoolean.GetInstance(taggedObject, false);
                }
            }
            return null;
        }

        private readonly int m_tagNo;
        private readonly Asn1Encodable m_obj;

        private PkiArchiveOptions(int tagNo, Asn1Encodable obj)
        {
            m_tagNo = tagNo;
            m_obj = obj ?? throw new ArgumentNullException(nameof(obj));
        }

        public PkiArchiveOptions(EncryptedKey encKey)
            : this(encryptedPrivKey, encKey)
        {
        }

        public PkiArchiveOptions(Asn1OctetString keyGenParameters)
            : this(PkiArchiveOptions.keyGenParameters, keyGenParameters)
        {
        }

        public PkiArchiveOptions(bool archiveRemGenPrivKey)
            : this(PkiArchiveOptions.archiveRemGenPrivKey, DerBoolean.GetInstance(archiveRemGenPrivKey))
        {
        }

        public virtual int Type => m_tagNo;

        public virtual Asn1Encodable Value => m_obj;

        /**
         * <pre>
         *  PkiArchiveOptions ::= CHOICE {
         *      encryptedPrivKey     [0] EncryptedKey,
         *      -- the actual value of the private key
         *      keyGenParameters     [1] KeyGenParameters,
         *      -- parameters which allow the private key to be re-generated
         *      archiveRemGenPrivKey [2] BOOLEAN }
         *      -- set to TRUE if sender wishes receiver to archive the private
         *      -- key of a key pair that the receiver generates in response to
         *      -- this request; set to FALSE if no archival is desired.
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            // NOTE: Explicit tagging automatically applied for EncryptedKey (a CHOICE)
            return new DerTaggedObject(false, m_tagNo, m_obj);
        }
    }
}
