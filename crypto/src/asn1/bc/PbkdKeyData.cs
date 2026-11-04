using System;

namespace Org.BouncyCastle.Asn1.BC
{
    /// <summary>
    /// Carrier for the contents of a <c>javax.crypto.interfaces.PBEKey</c> stored in a BCFKS keystore.
    /// </summary>
    /// <remarks>
    /// <code>
    /// PbkdKeyData ::= SEQUENCE {
    ///     keyAlgorithm    UTF8String,
    ///     password        OCTET STRING,
    ///     salt            [0] IMPLICIT OCTET STRING OPTIONAL,
    ///     iterationCount  [1] IMPLICIT INTEGER OPTIONAL,
    ///     encoded         [2] IMPLICIT OCTET STRING OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public sealed class PbkdKeyData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PbkdKeyData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PbkdKeyData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PbkdKeyData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PbkdKeyData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbkdKeyData pbkdKeyData)
                return pbkdKeyData;
            return new PbkdKeyData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PbkdKeyData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbkdKeyData"/>.</returns>
        public static PbkdKeyData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbkdKeyData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PbkdKeyData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbkdKeyData"/>.</returns>
        public static PbkdKeyData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbkdKeyData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerUtf8String m_keyAlgorithm;
        private readonly Asn1OctetString m_password;
        private readonly Asn1OctetString m_salt;
        private readonly DerInteger m_iterationCount;
        private readonly Asn1OctetString m_encoded;

        /// <summary>Create a new <see cref="PbkdKeyData"/>.</summary>
        /// <param name="keyAlgorithm">The key algorithm.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The iteration count.</param>
        /// <param name="encoded">The encoded form.</param>
        public PbkdKeyData(DerUtf8String keyAlgorithm, Asn1OctetString password, Asn1OctetString salt,
            DerInteger iterationCount, Asn1OctetString encoded)
        {
            m_keyAlgorithm = keyAlgorithm ?? throw new ArgumentNullException(nameof(keyAlgorithm));
            m_password = password ?? throw new ArgumentNullException(nameof(password));
        }

        private PbkdKeyData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyAlgorithm = Asn1Utilities.Read(seq, ref pos, DerUtf8String.GetInstance);
            m_password = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_salt = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1OctetString.GetTagged);
            m_iterationCount = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerInteger.GetTagged);
            m_encoded = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, Asn1OctetString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the encoded.</summary>
        public Asn1OctetString Encoded => m_encoded;

        /// <summary>Gets the iteration count.</summary>
        public DerInteger IterationCount => m_iterationCount;

        /// <summary>Gets the key algorithm.</summary>
        public DerUtf8String KeyAlgorithm => m_keyAlgorithm;

        /// <summary>Gets the password.</summary>
        public Asn1OctetString Password => m_password;

        /// <summary>Gets the salt.</summary>
        public Asn1OctetString Salt => m_salt;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_keyAlgorithm, m_password);
            v.AddOptionalTagged(false, 0, m_salt);
            v.AddOptionalTagged(false, 1, m_iterationCount);
            v.AddOptionalTagged(false, 2, m_encoded);
            return new DerSequence(v);
        }
    }
}
