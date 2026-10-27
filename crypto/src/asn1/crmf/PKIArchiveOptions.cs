using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The PKIArchiveOptions structure of RFC 4211, controlling the archiving of a private key.</summary>
    public class PkiArchiveOptions
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>The <c>encryptedPrivKey</c> constant, with the value <c>0</c>.</summary>
        public const int encryptedPrivKey = 0;
        /// <summary>The <c>keyGenParameters</c> constant, with the value <c>1</c>.</summary>
        public const int keyGenParameters = 1;
        /// <summary>The <c>archiveRemGenPrivKey</c> constant, with the value <c>2</c>.</summary>
        public const int archiveRemGenPrivKey = 2;

        /// <summary>Return an <see cref="PkiArchiveOptions"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PkiArchiveOptions"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PkiArchiveOptions"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiArchiveOptions GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="PkiArchiveOptions"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiArchiveOptions"/>.</returns>
        public static PkiArchiveOptions GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="PkiArchiveOptions"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="PkiArchiveOptions"/>, or null if <paramref name="element"/> is null.</returns>
        public static PkiArchiveOptions GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PkiArchiveOptions pkiArchiveOptions)
                return pkiArchiveOptions;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new PkiArchiveOptions(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        /// <summary>Return an <see cref="PkiArchiveOptions"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiArchiveOptions"/>.</returns>
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
                    return EncryptedKey.GetTagged(taggedObject, true);
                case keyGenParameters:
                    return Asn1OctetString.GetTagged(taggedObject, false);
                case archiveRemGenPrivKey:
                    return DerBoolean.GetTagged(taggedObject, false);
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

        /// <summary>Create a new <see cref="PkiArchiveOptions"/>.</summary>
        /// <param name="encKey">The enc key.</param>
        public PkiArchiveOptions(EncryptedKey encKey)
            : this(encryptedPrivKey, encKey)
        {
        }

        /// <summary>Create a new <see cref="PkiArchiveOptions"/>.</summary>
        /// <param name="keyGenParameters">The key gen parameters.</param>
        public PkiArchiveOptions(Asn1OctetString keyGenParameters)
            : this(PkiArchiveOptions.keyGenParameters, keyGenParameters)
        {
        }

        /// <summary>Create a new <see cref="PkiArchiveOptions"/>.</summary>
        /// <param name="archiveRemGenPrivKey">true if archive rem gen priv key, false otherwise.</param>
        public PkiArchiveOptions(bool archiveRemGenPrivKey)
            : this(PkiArchiveOptions.archiveRemGenPrivKey, DerBoolean.GetInstance(archiveRemGenPrivKey))
        {
        }

        /// <summary>Gets the type.</summary>
        public virtual int Type => m_tagNo;

        /// <summary>Gets the value.</summary>
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
