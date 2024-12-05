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
        public static BiometricData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BiometricData biometricData)
                return biometricData;
            return new BiometricData(Asn1Sequence.GetInstance(obj));
        }

        public static BiometricData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BiometricData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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

            m_typeOfBiometricData = TypeOfBiometricData.GetInstance(seq[pos++]);
			m_hashAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
			m_biometricDataHash = Asn1OctetString.GetInstance(seq[pos++]);
            m_sourceDataUri = Asn1Utilities.ReadOptional(seq, ref pos, DerIA5String.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm,
            Asn1OctetString biometricDataHash)
            : this(typeOfBiometricData, hashAlgorithm, biometricDataHash, null)
        {
        }

        public BiometricData(TypeOfBiometricData typeOfBiometricData, AlgorithmIdentifier hashAlgorithm,
            Asn1OctetString biometricDataHash, DerIA5String sourceDataUri)
        {
            m_typeOfBiometricData = typeOfBiometricData ?? throw new ArgumentNullException(nameof(typeOfBiometricData));
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_biometricDataHash = biometricDataHash ?? throw new ArgumentNullException(nameof(biometricDataHash));
            m_sourceDataUri = sourceDataUri;
        }

        public TypeOfBiometricData TypeOfBiometricData => m_typeOfBiometricData;

        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        public Asn1OctetString BiometricDataHash => m_biometricDataHash;

        public DerIA5String SourceDataUri => m_sourceDataUri;

        public override Asn1Object ToAsn1Object()
        {
            return m_sourceDataUri == null
                ?  new DerSequence(m_typeOfBiometricData, m_hashAlgorithm, m_biometricDataHash)
                :  new DerSequence(m_typeOfBiometricData, m_hashAlgorithm, m_biometricDataHash, m_sourceDataUri);
        }
    }
}
