using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// SigPolicyQualifierInfo ::= SEQUENCE {
    /// sigPolicyQualifierId  SigPolicyQualifierId,
    /// sigQualifier          ANY DEFINED BY sigPolicyQualifierId
    /// }
    ///
    /// SigPolicyQualifierId ::= OBJECT IDENTIFIER
    /// </code>
    /// </remarks>
    public class SigPolicyQualifierInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SigPolicyQualifierInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SigPolicyQualifierInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SigPolicyQualifierInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SigPolicyQualifierInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SigPolicyQualifierInfo sigPolicyQualifierInfo)
                return sigPolicyQualifierInfo;
            return new SigPolicyQualifierInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SigPolicyQualifierInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SigPolicyQualifierInfo"/>.</returns>
        public static SigPolicyQualifierInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SigPolicyQualifierInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SigPolicyQualifierInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SigPolicyQualifierInfo"/>.</returns>
        public static SigPolicyQualifierInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SigPolicyQualifierInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_sigPolicyQualifierId;
        private readonly Asn1Encodable m_sigQualifier;

        private SigPolicyQualifierInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_sigPolicyQualifierId = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_sigQualifier = Asn1Utilities.Read(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SigPolicyQualifierInfo"/>.</summary>
        /// <param name="sigPolicyQualifierId">The sig policy qualifier id.</param>
        /// <param name="sigQualifier">The sig qualifier.</param>
        public SigPolicyQualifierInfo(DerObjectIdentifier sigPolicyQualifierId, Asn1Encodable sigQualifier)
        {
            m_sigPolicyQualifierId = sigPolicyQualifierId ?? throw new ArgumentNullException(nameof(sigPolicyQualifierId));
            m_sigQualifier = sigQualifier ?? throw new ArgumentNullException(nameof(sigQualifier));
        }

        /// <summary>Gets the sig policy qualifier id.</summary>
        public DerObjectIdentifier SigPolicyQualifierId => m_sigPolicyQualifierId;

        /// <summary>Gets the sig qualifier data.</summary>
        public Asn1Encodable SigQualifierData => m_sigQualifier;

        /// <summary>Gets the sig qualifier.</summary>
        [Obsolete("Use 'SigQualifierData' instead")]
        public Asn1Object SigQualifier => m_sigQualifier.ToAsn1Object();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_sigPolicyQualifierId, m_sigQualifier);
    }
}
