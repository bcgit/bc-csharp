using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The EncryptedValue structure of RFC 4211.</summary>
    public class EncryptedValue
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EncryptedValue"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EncryptedValue"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EncryptedValue"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EncryptedValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedValue encryptedValue)
                return encryptedValue;
            return new EncryptedValue(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EncryptedValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedValue"/>.</returns>
        public static EncryptedValue GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedValue(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="EncryptedValue"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="EncryptedValue"/>, or null if <paramref name="element"/> is null.</returns>
        public static EncryptedValue GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is EncryptedValue encryptedValue)
                return encryptedValue;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new EncryptedValue(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="EncryptedValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedValue"/>.</returns>
        public static EncryptedValue GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EncryptedValue(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_intendedAlg;
        private readonly AlgorithmIdentifier m_symmAlg;
        private readonly DerBitString m_encSymmKey;
        private readonly AlgorithmIdentifier m_keyAlg;
        private readonly Asn1OctetString m_valueHint;
        private readonly DerBitString m_encValue;

        private EncryptedValue(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_intendedAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, AlgorithmIdentifier.GetTagged);
            m_symmAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, AlgorithmIdentifier.GetTagged);
            m_encSymmKey = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, DerBitString.GetTagged);
            m_keyAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, false, AlgorithmIdentifier.GetTagged);
            m_valueHint = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, false, Asn1OctetString.GetTagged);
            m_encValue = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="EncryptedValue"/>.</summary>
        /// <param name="intendedAlg">The intended alg.</param>
        /// <param name="symmAlg">The symm alg.</param>
        /// <param name="encSymmKey">The enc symm key.</param>
        /// <param name="keyAlg">The key alg.</param>
        /// <param name="valueHint">The value hint.</param>
        /// <param name="encValue">The enc value.</param>
        public EncryptedValue(AlgorithmIdentifier intendedAlg, AlgorithmIdentifier symmAlg, DerBitString encSymmKey,
            AlgorithmIdentifier keyAlg, Asn1OctetString valueHint, DerBitString encValue)
        {
            m_intendedAlg = intendedAlg;
            m_symmAlg = symmAlg;
            m_encSymmKey = encSymmKey;
            m_keyAlg = keyAlg;
            m_valueHint = valueHint;
            m_encValue = encValue ?? throw new ArgumentNullException(nameof(encValue));
        }

        /// <summary>Gets the intended alg.</summary>
        public virtual AlgorithmIdentifier IntendedAlg => m_intendedAlg;

        /// <summary>Gets the symm alg.</summary>
        public virtual AlgorithmIdentifier SymmAlg => m_symmAlg;

        /// <summary>Gets the enc symm key.</summary>
        public virtual DerBitString EncSymmKey => m_encSymmKey;

        /// <summary>Gets the key alg.</summary>
        public virtual AlgorithmIdentifier KeyAlg => m_keyAlg;

        /// <summary>Gets the value hint.</summary>
        public virtual Asn1OctetString ValueHint => m_valueHint;

        /// <summary>Gets the enc value.</summary>
        public virtual DerBitString EncValue => m_encValue;

        /**
         * <pre>
         * (IMPLICIT TAGS)
         * EncryptedValue ::= SEQUENCE {
         *                     intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
         *                     -- the intended algorithm for which the value will be used
         *                     symmAlg       [1] AlgorithmIdentifier  OPTIONAL,
         *                     -- the symmetric algorithm used to encrypt the value
         *                     encSymmKey    [2] BIT STRING           OPTIONAL,
         *                     -- the (encrypted) symmetric key used to encrypt the value
         *                     keyAlg        [3] AlgorithmIdentifier  OPTIONAL,
         *                     -- algorithm used to encrypt the symmetric key
         *                     valueHint     [4] OCTET STRING         OPTIONAL,
         *                     -- a brief description or identifier of the encValue content
         *                     -- (may be meaningful only to the sending entity, and used only
         *                     -- if EncryptedValue might be re-examined by the sending entity
         *                     -- in the future)
         *                     encValue       BIT STRING }
         *                     -- the encrypted value itself
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(6);
            v.AddOptionalTagged(false, 0, m_intendedAlg);
            v.AddOptionalTagged(false, 1, m_symmAlg);
            v.AddOptionalTagged(false, 2, m_encSymmKey);
            v.AddOptionalTagged(false, 3, m_keyAlg);
            v.AddOptionalTagged(false, 4, m_valueHint);
            v.Add(m_encValue);
            return new DerSequence(v);
        }
    }
}
