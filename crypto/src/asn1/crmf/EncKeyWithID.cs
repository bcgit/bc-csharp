using System;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The EncKeyWithID structure of RFC 4211: a private key and an identifier.</summary>
    public class EncKeyWithID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EncKeyWithID"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EncKeyWithID"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EncKeyWithID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EncKeyWithID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncKeyWithID encKeyWithID)
                return encKeyWithID;
            return new EncKeyWithID(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EncKeyWithID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncKeyWithID"/>.</returns>
        public static EncKeyWithID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncKeyWithID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="EncKeyWithID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncKeyWithID"/>.</returns>
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
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_privKeyInfo = Asn1Utilities.Read(seq, ref pos, PrivateKeyInfo.GetInstance);
            m_identifier = Asn1Utilities.ReadOptional(seq, ref pos, GetOptionalChoice);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        private EncKeyWithID(PrivateKeyInfo privKeyInfo, Asn1Encodable identifier)
        {
            m_privKeyInfo = privKeyInfo ?? throw new ArgumentNullException(nameof(privKeyInfo));
            m_identifier = identifier;
        }

        /// <summary>Create a new <see cref="EncKeyWithID"/>.</summary>
        /// <param name="privKeyInfo">The priv key info.</param>
        public EncKeyWithID(PrivateKeyInfo privKeyInfo)
            : this(privKeyInfo, (Asn1Encodable)null)
        {
        }

        /// <summary>Create a new <see cref="EncKeyWithID"/>.</summary>
        /// <param name="privKeyInfo">The priv key info.</param>
        /// <param name="str">The str.</param>
        public EncKeyWithID(PrivateKeyInfo privKeyInfo, DerUtf8String str)
            : this(privKeyInfo, (Asn1Encodable)str)
        {
        }

        /// <summary>Create a new <see cref="EncKeyWithID"/>.</summary>
        /// <param name="privKeyInfo">The priv key info.</param>
        /// <param name="generalName">The general name.</param>
        public EncKeyWithID(PrivateKeyInfo privKeyInfo, GeneralName generalName)
            : this(privKeyInfo, (Asn1Encodable)generalName)
        {
        }

        /// <summary>Gets the private key.</summary>
        public virtual PrivateKeyInfo PrivateKey => m_privKeyInfo;

        /// <summary>Gets a value indicating whether this has identifier.</summary>
        public virtual bool HasIdentifier => m_identifier != null;

        /// <summary>Gets a value indicating whether this is identifier utf 8 string.</summary>
        public virtual bool IsIdentifierUtf8String => m_identifier is DerUtf8String;

        /// <summary>Gets the identifier.</summary>
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
