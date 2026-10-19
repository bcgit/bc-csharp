using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The EncryptedData structure of RFC 5652.</summary>
    public class EncryptedData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EncryptedData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EncryptedData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EncryptedData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EncryptedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedData encryptedData)
                return encryptedData;
            return new EncryptedData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EncryptedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedData"/>.</returns>
        public static EncryptedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="EncryptedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedData"/>.</returns>
        public static EncryptedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly EncryptedContentInfo m_encryptedContentInfo;
        private readonly Asn1Set m_unprotectedAttrs;

        /// <summary>Create a new <see cref="EncryptedData"/>.</summary>
        /// <param name="encInfo">The enc info.</param>
        public EncryptedData(EncryptedContentInfo encInfo)
            : this(encInfo, null)
        {
        }

        /// <summary>Create a new <see cref="EncryptedData"/>.</summary>
        /// <param name="encInfo">The enc info.</param>
        /// <param name="unprotectedAttrs">The unprotected attrs.</param>
        public EncryptedData(EncryptedContentInfo encInfo, Asn1Set unprotectedAttrs)
        {
            m_version = unprotectedAttrs == null ? DerInteger.Zero : DerInteger.Two;
            m_encryptedContentInfo = encInfo ?? throw new ArgumentNullException(nameof(encInfo));
            m_unprotectedAttrs = unprotectedAttrs;
        }

        private EncryptedData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_encryptedContentInfo = Asn1Utilities.Read(seq, ref pos, EncryptedContentInfo.GetInstance);
            m_unprotectedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public virtual DerInteger Version => m_version;

        public virtual EncryptedContentInfo EncryptedContentInfo => m_encryptedContentInfo;

        /// <summary>Gets the unprotected attrs.</summary>
        public virtual Asn1Set UnprotectedAttrs => m_unprotectedAttrs;

        /**
        * <pre>
        *       EncryptedData ::= SEQUENCE {
        *                     version CMSVersion,
        *                     encryptedContentInfo EncryptedContentInfo,
        *                     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
        * </pre>
        * @return a basic ASN.1 object representation.
        */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_version, m_encryptedContentInfo);

            if (m_unprotectedAttrs != null)
            {
                v.Add(new BerTaggedObject(false, 1, m_unprotectedAttrs));
            }

            return new BerSequence(v);
        }
    }
}
