using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /**
    * The BiometricData object.
    * <pre>
    * BiometricData  ::=  SEQUENCE {
    *       typeOfBiometricData  TypeOfBiometricData,
    *       hashAlgorithm        AlgorithmIdentifier,
    *       biometricDataHash    OCTET STRING,
    *       sourceDataUri        IA5String OPTIONAL  }
    * </pre>
    */
    public class BiometricData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="BiometricData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="BiometricData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="BiometricData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static BiometricData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BiometricData biometricData)
                return biometricData;
            return new BiometricData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="BiometricData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BiometricData"/>.</returns>
        public static BiometricData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BiometricData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="BiometricData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BiometricData"/>.</returns>
        public static BiometricData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BiometricData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly TypeOfBiometricData m_typeOfBiometricData;
        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly Asn1OctetString m_biometricDataHash;
        private readonly DerIA5String m_sourceDataUri;

        private BiometricData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_typeOfBiometricData = Asn1Utilities.Read(seq, ref pos, TypeOfBiometricData.GetInstance);
            m_hashAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_biometricDataHash = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_sourceDataUri = Asn1Utilities.ReadOptional(seq, ref pos, DerIA5String.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="BiometricData"/>.</summary>
        /// <param name="typeOfBiometricData">The type of biometric data.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="biometricDataHash">The biometric data hash.</param>
        public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm,
            Asn1OctetString biometricDataHash)
            : this(typeOfBiometricData, hashAlgorithm, biometricDataHash, null)
        {
        }

        /// <summary>Create a new <see cref="BiometricData"/>.</summary>
        /// <param name="typeOfBiometricData">The type of biometric data.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="biometricDataHash">The biometric data hash.</param>
        /// <param name="sourceDataUri">The source data uri.</param>
        public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm,
            Asn1OctetString biometricDataHash, DerIA5String sourceDataUri)
        {
            m_typeOfBiometricData = typeOfBiometricData ?? throw new ArgumentNullException(nameof(typeOfBiometricData));
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_biometricDataHash = biometricDataHash ?? throw new ArgumentNullException(nameof(biometricDataHash));
            m_sourceDataUri = sourceDataUri;
        }

        /// <summary>Gets the type of biometric data.</summary>
        public TypeOfBiometricData TypeOfBiometricData => m_typeOfBiometricData;

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Gets the biometric data hash.</summary>
        public Asn1OctetString BiometricDataHash => m_biometricDataHash;

        /// <summary>Gets the source data uri.</summary>
        public DerIA5String SourceDataUri => m_sourceDataUri;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return m_sourceDataUri == null
                ?  new DerSequence(m_typeOfBiometricData, m_hashAlgorithm, m_biometricDataHash)
                :  new DerSequence(m_typeOfBiometricData, m_hashAlgorithm, m_biometricDataHash, m_sourceDataUri);
        }
    }
}
