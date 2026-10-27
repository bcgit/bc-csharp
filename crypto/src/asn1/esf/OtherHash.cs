using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// OtherHash ::= CHOICE {
    /// sha1Hash OtherHashValue, -- This contains a SHA-1 hash
    /// 	otherHash OtherHashAlgAndValue
    /// }
    ///
    /// OtherHashValue ::= OCTET STRING
    /// </code>
    /// </remarks>
    public class OtherHash
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="OtherHash"/> from the given object.</summary>
        /// <param name="obj">An <see cref="OtherHash"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="OtherHash"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OtherHash GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="OtherHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherHash"/>.</returns>
        public static OtherHash GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="OtherHash"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="OtherHash"/>, or null if <paramref name="element"/> is null.</returns>
        public static OtherHash GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OtherHash existing)
                return existing;

            Asn1OctetString sha1Hash = Asn1OctetString.GetOptional(element);
            if (sha1Hash != null)
                return new OtherHash(sha1Hash);

            OtherHashAlgAndValue otherHash = OtherHashAlgAndValue.GetOptional(element);
            if (otherHash != null)
                return new OtherHash(otherHash);

            return null;
        }

        /// <summary>Return an <see cref="OtherHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OtherHash"/>.</returns>
        public static OtherHash GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1OctetString m_sha1Hash;
        private readonly OtherHashAlgAndValue m_otherHash;

        /// <summary>Create a new <see cref="OtherHash"/>.</summary>
        /// <param name="sha1Hash">The sha 1 hash.</param>
        public OtherHash(byte[] sha1Hash)
        {
            m_sha1Hash = DerOctetString.FromContents(sha1Hash);
        }

        /// <summary>Create a new <see cref="OtherHash"/>.</summary>
        /// <param name="sha1Hash">The sha 1 hash.</param>
        public OtherHash(Asn1OctetString sha1Hash)
        {
            m_sha1Hash = sha1Hash ?? throw new ArgumentNullException(nameof(sha1Hash));
        }

        /// <summary>Create a new <see cref="OtherHash"/>.</summary>
        /// <param name="otherHash">The other hash.</param>
        public OtherHash(OtherHashAlgAndValue otherHash)
        {
            m_otherHash = otherHash ?? throw new ArgumentNullException(nameof(otherHash));
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm =>
            m_otherHash?.HashAlgorithm ?? new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);

        /// <summary>Return the hash value.</summary>
        public byte[] GetHashValue() => m_otherHash?.GetHashValue() ?? m_sha1Hash.GetOctets();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_otherHash?.ToAsn1Object() ?? m_sha1Hash;
    }
}
