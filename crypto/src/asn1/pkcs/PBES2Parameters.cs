using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The PBES2-params structure of PKCS#5 v2.1.</summary>
    public class PbeS2Parameters
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PbeS2Parameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PbeS2Parameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PbeS2Parameters"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PbeS2Parameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbeS2Parameters pbeS2Parameters)
                return pbeS2Parameters;
            return new PbeS2Parameters(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PbeS2Parameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbeS2Parameters"/>.</returns>
        public static PbeS2Parameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeS2Parameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PbeS2Parameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PbeS2Parameters"/>.</returns>
        public static PbeS2Parameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeS2Parameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly KeyDerivationFunc m_func;
        private readonly EncryptionScheme m_scheme;

        private PbeS2Parameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            AlgorithmIdentifier func = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_func = new KeyDerivationFunc(func.Algorithm, func.Parameters);

            m_scheme = Asn1Utilities.Read(seq, ref pos, EncryptionScheme.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="PbeS2Parameters"/>.</summary>
        /// <param name="keyDevFunc">The key dev func.</param>
        /// <param name="encScheme">The enc scheme.</param>
        public PbeS2Parameters(KeyDerivationFunc keyDevFunc, EncryptionScheme encScheme)
        {
            m_func = keyDevFunc ?? throw new ArgumentNullException(nameof(keyDevFunc));
            m_scheme = encScheme ?? throw new ArgumentNullException(nameof(encScheme));
        }

        /// <summary>Gets the key derivation func.</summary>
        public KeyDerivationFunc KeyDerivationFunc => m_func;

        /// <summary>Gets the encryption scheme.</summary>
        public EncryptionScheme EncryptionScheme => m_scheme;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_func, m_scheme);
    }
}
