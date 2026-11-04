using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// SignaturePolicyId ::= SEQUENCE {
    /// 	sigPolicyIdentifier SigPolicyId,
    /// 	sigPolicyHash SigPolicyHash,
    /// 	sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL
    /// }
    ///
    /// SigPolicyId ::= OBJECT IDENTIFIER
    ///
    /// SigPolicyHash ::= OtherHashAlgAndValue
    /// </code>
    /// </remarks>
    public class SignaturePolicyId
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SignaturePolicyId"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SignaturePolicyId"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SignaturePolicyId"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SignaturePolicyId GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignaturePolicyId signaturePolicyId)
                return signaturePolicyId;
            return new SignaturePolicyId(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SignaturePolicyId"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignaturePolicyId"/>.</returns>
        public static SignaturePolicyId GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignaturePolicyId(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SignaturePolicyId"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="SignaturePolicyId"/>, or null if <paramref name="element"/> is null.</returns>
        public static SignaturePolicyId GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is SignaturePolicyId signaturePolicyId)
                return signaturePolicyId;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new SignaturePolicyId(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="SignaturePolicyId"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignaturePolicyId"/>.</returns>
        public static SignaturePolicyId GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignaturePolicyId(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_sigPolicyIdentifier;
        private readonly OtherHashAlgAndValue m_sigPolicyHash;
        private readonly Asn1Sequence m_sigPolicyQualifiers;

        private SignaturePolicyId(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_sigPolicyIdentifier = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_sigPolicyHash = Asn1Utilities.Read(seq, ref pos, OtherHashAlgAndValue.GetInstance);
            m_sigPolicyQualifiers = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SignaturePolicyId"/>.</summary>
        /// <param name="sigPolicyIdentifier">The sig policy identifier.</param>
        /// <param name="sigPolicyHash">The sig policy hash.</param>
        public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash)
            : this(sigPolicyIdentifier, sigPolicyHash, null)
        {
        }

        /// <summary>Create a new <see cref="SignaturePolicyId"/>.</summary>
        /// <param name="sigPolicyIdentifier">The sig policy identifier.</param>
        /// <param name="sigPolicyHash">The sig policy hash.</param>
        /// <param name="sigPolicyQualifiers">The sig policy qualifiers.</param>
        public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash,
            params SigPolicyQualifierInfo[] sigPolicyQualifiers)
        {
            m_sigPolicyIdentifier = sigPolicyIdentifier ?? throw new ArgumentNullException(nameof(sigPolicyIdentifier));
            m_sigPolicyHash = sigPolicyHash ?? throw new ArgumentNullException(nameof(sigPolicyHash));
            m_sigPolicyQualifiers = DerSequence.FromElementsOptional(sigPolicyQualifiers);
        }

        /// <summary>Create a new <see cref="SignaturePolicyId"/>.</summary>
        /// <param name="sigPolicyIdentifier">The sig policy identifier.</param>
        /// <param name="sigPolicyHash">The sig policy hash.</param>
        /// <param name="sigPolicyQualifiers">The sig policy qualifiers.</param>
        public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash,
            IEnumerable<SigPolicyQualifierInfo> sigPolicyQualifiers)
        {
            m_sigPolicyIdentifier = sigPolicyIdentifier ?? throw new ArgumentNullException(nameof(sigPolicyIdentifier));
            m_sigPolicyHash = sigPolicyHash ?? throw new ArgumentNullException(nameof(sigPolicyHash));

            if (sigPolicyQualifiers != null)
            {
                m_sigPolicyQualifiers = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(sigPolicyQualifiers));
            }
        }

        /// <summary>Create a new <see cref="SignaturePolicyId"/>.</summary>
        /// <param name="sigPolicyIdentifier">The sig policy identifier.</param>
        /// <param name="sigPolicyHash">The sig policy hash.</param>
        /// <param name="sigPolicyQualifiers">The sig policy qualifiers.</param>
        public SignaturePolicyId(DerObjectIdentifier sigPolicyIdentifier, OtherHashAlgAndValue sigPolicyHash,
            IReadOnlyCollection<SigPolicyQualifierInfo> sigPolicyQualifiers)
        {
            m_sigPolicyIdentifier = sigPolicyIdentifier ?? throw new ArgumentNullException(nameof(sigPolicyIdentifier));
            m_sigPolicyHash = sigPolicyHash ?? throw new ArgumentNullException(nameof(sigPolicyHash));

            if (sigPolicyQualifiers != null)
            {
                m_sigPolicyQualifiers = DerSequence.FromCollection(sigPolicyQualifiers);
            }
        }

        /// <summary>Gets the sig policy identifier.</summary>
        public DerObjectIdentifier SigPolicyIdentifier => m_sigPolicyIdentifier;

        /// <summary>Gets the sig policy hash.</summary>
        public OtherHashAlgAndValue SigPolicyHash => m_sigPolicyHash;

        /// <summary>Return the sig policy qualifiers.</summary>
        public SigPolicyQualifierInfo[] GetSigPolicyQualifiers() =>
            m_sigPolicyQualifiers?.MapElements(SigPolicyQualifierInfo.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_sigPolicyIdentifier, m_sigPolicyHash);
            v.AddOptional(m_sigPolicyQualifiers);
            return new DerSequence(v);
        }
    }
}
