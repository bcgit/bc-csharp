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
        /// <summary>The <c>Picture</c> constant, with the value <c>0</c>.</summary>
        public const int Picture = 0;
        /// <summary>The <c>HandwrittenSignature</c> constant, with the value <c>1</c>.</summary>
        public const int HandwrittenSignature = 1;

        /// <summary>Return an <see cref="TypeOfBiometricData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TypeOfBiometricData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TypeOfBiometricData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TypeOfBiometricData GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="TypeOfBiometricData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TypeOfBiometricData"/>.</returns>
        public static TypeOfBiometricData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="TypeOfBiometricData"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="TypeOfBiometricData"/>, or null if <paramref name="element"/> is null.</returns>
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

        /// <summary>Return an <see cref="TypeOfBiometricData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TypeOfBiometricData"/>.</returns>
        public static TypeOfBiometricData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_obj;

        /// <summary>Create a new <see cref="TypeOfBiometricData"/>.</summary>
        /// <param name="predefinedBiometricType">The predefined biometric type.</param>
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

        /// <summary>Create a new <see cref="TypeOfBiometricData"/>.</summary>
        /// <param name="biometricDataOid">The biometric data oid.</param>
        public TypeOfBiometricData(DerObjectIdentifier biometricDataOid)
        {
            m_obj = biometricDataOid;
        }

        /// <summary>Gets a value indicating whether this is predefined.</summary>
        public bool IsPredefined => m_obj is DerInteger;

        /// <summary>Gets the predefined biometric type.</summary>
        public int PredefinedBiometricType => ((DerInteger)m_obj).IntValueExact;

        /// <summary>Gets the biometric data oid.</summary>
        public DerObjectIdentifier BiometricDataOid => (DerObjectIdentifier)m_obj;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_obj.ToAsn1Object();
    }
}
