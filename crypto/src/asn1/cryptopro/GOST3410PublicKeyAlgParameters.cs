using System;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    /// <summary>
    /// The AlgorithmIdentifier parameters for GOST R 34.10-2001 and GOST R 34.10-2012 keys.
    /// </summary>
    /// <remarks>
    /// This type covers two structures:
    /// <code>
    /// GostR3410-2001-PublicKeyParameters ::= SEQUENCE {      -- RFC 4491, Section 2.3.2
    ///     publicKeyParamSet   OBJECT IDENTIFIER,
    ///     digestParamSet      OBJECT IDENTIFIER,
    ///     encryptionParamSet  OBJECT IDENTIFIER DEFAULT id-Gost28147-89-CryptoPro-A-ParamSet
    /// }
    ///
    /// GostR3410-2012-PublicKeyParameters ::= SEQUENCE {      -- RFC 9215, Section 4.2
    ///     publicKeyParamSet   OBJECT IDENTIFIER,
    ///     digestParamSet      OBJECT IDENTIFIER OPTIONAL
    /// }
    /// </code>
    /// digestParamSet and encryptionParamSet are consecutive, untagged, and of the same type, so a second element
    /// cannot be distinguished by type alone. It is always digestParamSet: the 2001 structure requires
    /// digestParamSet ahead of the DEFAULT encryptionParamSet, and the 2012 structure has no encryptionParamSet.
    /// </remarks>
    public class Gost3410PublicKeyAlgParameters
        : Asn1Encodable
    {
        public static Gost3410PublicKeyAlgParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Gost3410PublicKeyAlgParameters gost3410PublicKeyAlgParameters)
                return gost3410PublicKeyAlgParameters;
            return new Gost3410PublicKeyAlgParameters(Asn1Sequence.GetInstance(obj));
        }

        public static Gost3410PublicKeyAlgParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost3410PublicKeyAlgParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Gost3410PublicKeyAlgParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost3410PublicKeyAlgParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_publicKeyParamSet;
        private readonly DerObjectIdentifier m_digestParamSet;
        private readonly DerObjectIdentifier m_encryptionParamSet;

        private Gost3410PublicKeyAlgParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_publicKeyParamSet = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);

            // NOTE: Two consecutive untagged OPTIONALs of the same type cannot be told apart by the reads below; the
            // greedy assignment (a second element is always digestParamSet) is correct here only because of the
            // structure rules recorded in the class documentation.
            m_digestParamSet = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);
            m_encryptionParamSet = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Gost3410PublicKeyAlgParameters(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet)
            : this(publicKeyParamSet, digestParamSet, null)
        {
        }

        /// <param name="publicKeyParamSet">The public key parameter set; required.</param>
        /// <param name="digestParamSet">The digest parameter set; may be null for GOST R 34.10-2012 keys (RFC 9215,
        /// Section 4.2), but is required for GOST R 34.10-2001 keys (RFC 4491, Section 2.3.2).</param>
        /// <param name="encryptionParamSet">The encryption parameter set; may be null. Only meaningful with a
        /// non-null <paramref name="digestParamSet"/>, since it can only be encoded as the third element.</param>
        public Gost3410PublicKeyAlgParameters(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet,
            DerObjectIdentifier encryptionParamSet)
        {
            if (digestParamSet == null && encryptionParamSet != null)
                throw new ArgumentException("encryptionParamSet requires digestParamSet", nameof(encryptionParamSet));

            m_publicKeyParamSet = publicKeyParamSet ?? throw new ArgumentNullException(nameof(publicKeyParamSet));
            m_digestParamSet = digestParamSet;
            m_encryptionParamSet = encryptionParamSet;
        }

        public DerObjectIdentifier PublicKeyParamSet => m_publicKeyParamSet;

		public DerObjectIdentifier DigestParamSet => m_digestParamSet;

		public DerObjectIdentifier EncryptionParamSet => m_encryptionParamSet;

		public override Asn1Object ToAsn1Object()
        {
            if (m_digestParamSet == null)
                return new DerSequence(m_publicKeyParamSet);

            return m_encryptionParamSet == null
                ?  new DerSequence(m_publicKeyParamSet, m_digestParamSet)
                :  new DerSequence(m_publicKeyParamSet, m_digestParamSet, m_encryptionParamSet);
        }
    }
}
