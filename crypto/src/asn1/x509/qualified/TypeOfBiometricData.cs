using System;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    /**
     * The TypeOfBiometricData object.
     * <pre>
     * TypeOfBiometricData ::= CHOICE {
     *   predefinedBiometricType   PredefinedBiometricType,
     *   biometricDataOid          OBJECT IDENTIFIER }
     *
     * PredefinedBiometricType ::= INTEGER {
     *   picture(0),handwritten-signature(1)}
     *   (picture|handwritten-signature)
     * </pre>
     */
    public class TypeOfBiometricData
        : Asn1Encodable, IAsn1Choice
    {
        public const int Picture = 0;
        public const int HandwrittenSignature = 1;

        public static TypeOfBiometricData GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static TypeOfBiometricData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static TypeOfBiometricData GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is TypeOfBiometricData typeOfBiometricData)
                return typeOfBiometricData;

            DerInteger predefinedBiometricType = DerInteger.GetOptional(element);
            if (predefinedBiometricType != null)
                return new TypeOfBiometricData(predefinedBiometricType.IntValueExact);

            DerObjectIdentifier biometricDataOid = DerObjectIdentifier.GetOptional(element);
            if (biometricDataOid != null)
                return new TypeOfBiometricData(biometricDataOid);

            return null;
        }

        public static TypeOfBiometricData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_obj;

        public TypeOfBiometricData(int predefinedBiometricType)
        {
            if (predefinedBiometricType == Picture || predefinedBiometricType == HandwrittenSignature)
            {
                m_obj = DerInteger.ValueOf(predefinedBiometricType);
            }
            else
            {
                throw new ArgumentException("unknow PredefinedBiometricType : " + predefinedBiometricType);
            }
        }

        public TypeOfBiometricData(DerObjectIdentifier biometricDataOid)
        {
            m_obj = biometricDataOid;
        }

        public bool IsPredefined => m_obj is DerInteger;

        public int PredefinedBiometricType => ((DerInteger)m_obj).IntValueExact;

        public DerObjectIdentifier BiometricDataOid => (DerObjectIdentifier)m_obj;

        public override Asn1Object ToAsn1Object() => m_obj.ToAsn1Object();
    }
}
