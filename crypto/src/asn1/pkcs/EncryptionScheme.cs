using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The EncryptionScheme algorithm identifier of PKCS#5 v2.1.</summary>
    // TODO[api] This is not supposed to be a separate type; remove and use AlgorithmIdentifier
    public class EncryptionScheme
        : AlgorithmIdentifier
    {
        /// <summary>Return an <see cref="EncryptionScheme"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EncryptionScheme"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EncryptionScheme"/>, or null if <paramref name="obj"/> is null.</returns>
        public new static EncryptionScheme GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptionScheme encryptionScheme)
                return encryptionScheme;
            return new EncryptionScheme(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EncryptionScheme"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptionScheme"/>.</returns>
        public new static EncryptionScheme GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptionScheme(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="EncryptionScheme"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptionScheme"/>.</returns>
        public new static EncryptionScheme GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptionScheme(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        /// <summary>Create a new <see cref="EncryptionScheme"/>.</summary>
        /// <param name="objectID">The object ID.</param>
        public EncryptionScheme(
            DerObjectIdentifier objectID)
            : base(objectID)
        {
        }

        /// <summary>Create a new <see cref="EncryptionScheme"/>.</summary>
        /// <param name="objectID">The object ID.</param>
        /// <param name="parameters">The parameters.</param>
        public EncryptionScheme(
            DerObjectIdentifier objectID,
            Asn1Encodable parameters)
            : base(objectID, parameters)
        {
        }

        internal EncryptionScheme(
            Asn1Sequence seq)
            : this((DerObjectIdentifier)seq[0], seq[1])
        {
        }

        /// <summary>Gets the asn 1 object.</summary>
        public Asn1Object Asn1Object
        {
            get { return Parameters.ToAsn1Object(); }
        }

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(Algorithm, Parameters);
        }
    }
}
