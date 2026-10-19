using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// CrlValidatedID ::= SEQUENCE {
    /// crlHash OtherHash,
    /// crlIdentifier CrlIdentifier OPTIONAL}
    /// </code>
    /// </remarks>
    public class CrlValidatedID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlValidatedID"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CrlValidatedID"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CrlValidatedID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlValidatedID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlValidatedID crlValidatedID)
                return crlValidatedID;
            return new CrlValidatedID(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CrlValidatedID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlValidatedID"/>.</returns>
        public static CrlValidatedID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlValidatedID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CrlValidatedID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlValidatedID"/>.</returns>
        public static CrlValidatedID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlValidatedID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OtherHash m_crlHash;
        private readonly CrlIdentifier m_crlIdentifier;

        private CrlValidatedID(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_crlHash = Asn1Utilities.Read(seq, ref pos, OtherHash.GetInstance);
            m_crlIdentifier = Asn1Utilities.ReadOptional(seq, ref pos, CrlIdentifier.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CrlValidatedID"/>.</summary>
        /// <param name="crlHash">The crl hash.</param>
        public CrlValidatedID(OtherHash crlHash)
            : this(crlHash, null)
        {
        }

        /// <summary>Create a new <see cref="CrlValidatedID"/>.</summary>
        /// <param name="crlHash">The crl hash.</param>
        /// <param name="crlIdentifier">The crl identifier.</param>
        public CrlValidatedID(OtherHash crlHash, CrlIdentifier crlIdentifier)
        {
            m_crlHash = crlHash ?? throw new ArgumentNullException(nameof(crlHash));
            m_crlIdentifier = crlIdentifier;
        }

        /// <summary>Gets the crl hash.</summary>
        public OtherHash CrlHash => m_crlHash;

        public CrlIdentifier CrlIdentifier => m_crlIdentifier;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_crlHash);
            v.AddOptional(m_crlIdentifier);
            return new DerSequence(v);
        }
    }
}
