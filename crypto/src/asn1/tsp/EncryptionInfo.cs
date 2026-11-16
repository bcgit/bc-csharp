using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of the EncryptionInfo element defined in RFC 4998:
     * <p/>
     * 1988 ASN.1 EncryptionInfo
     * <p/>
     * EncryptionInfo       ::=     SEQUENCE {
     * encryptionInfoType     OBJECT IDENTIFIER,
     * encryptionInfoValue    ANY DEFINED BY encryptionInfoType
     * }
     * <p/>
     * 1997-ASN.1 EncryptionInfo
     * <p/>
     * EncryptionInfo       ::=     SEQUENCE {
     * encryptionInfoType   ENCINFO-TYPE.&amp;id
     * ({SupportedEncryptionAlgorithms}),
     * encryptionInfoValue  ENCINFO-TYPE.&amp;Type
     * ({SupportedEncryptionAlgorithms}{&#064;encryptionInfoType})
     * }
     * <p/>
     * ENCINFO-TYPE ::= TYPE-IDENTIFIER
     * <p/>
     * SupportedEncryptionAlgorithms ENCINFO-TYPE ::= {...}
     */
    public class EncryptionInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EncryptionInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EncryptionInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EncryptionInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EncryptionInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptionInfo encryptionInfo)
                return encryptionInfo;
            return new EncryptionInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EncryptionInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptionInfo"/>.</returns>
        public static EncryptionInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptionInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="EncryptionInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptionInfo"/>.</returns>
        public static EncryptionInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptionInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        /**
         * The OID for EncryptionInfo type.
         */
        private readonly DerObjectIdentifier m_encryptionInfoType;

        /**
         * The value of EncryptionInfo
         */
        private readonly Asn1Encodable m_encryptionInfoValue;

        private EncryptionInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_encryptionInfoType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_encryptionInfoValue = Asn1Utilities.Read(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="EncryptionInfo"/>.</summary>
        /// <param name="encryptionInfoType">The encryption info type.</param>
        /// <param name="encryptionInfoValue">The encryption info value.</param>
        public EncryptionInfo(DerObjectIdentifier encryptionInfoType, Asn1Encodable encryptionInfoValue)
        {
            m_encryptionInfoType = encryptionInfoType ?? throw new ArgumentNullException(nameof(encryptionInfoType));
            m_encryptionInfoValue = encryptionInfoValue ?? throw new ArgumentNullException(nameof(encryptionInfoValue));
        }

        /// <summary>Gets the encryption info type.</summary>
        public virtual DerObjectIdentifier EncryptionInfoType => m_encryptionInfoType;

        /// <summary>Gets the encryption info value.</summary>
        public virtual Asn1Encodable EncryptionInfoValue => m_encryptionInfoValue;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DLSequence(m_encryptionInfoType, m_encryptionInfoValue);
    }
}
