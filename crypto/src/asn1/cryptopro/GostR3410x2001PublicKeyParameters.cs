using System;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    /// <summary>
    /// The AlgorithmIdentifier parameters for GOST R 34.10-2001 keys (RFC 4491, Section 2.3.2).
    /// </summary>
    /// <remarks>
    /// <code>
    /// GostR3410-2001-PublicKeyParameters ::= SEQUENCE {
    ///     publicKeyParamSet   OBJECT IDENTIFIER,
    ///     digestParamSet      OBJECT IDENTIFIER,
    ///     encryptionParamSet  OBJECT IDENTIFIER DEFAULT id-Gost28147-89-CryptoPro-A-ParamSet
    /// }
    /// </code>
    /// An absent encryptionParamSet is reported as <see cref="DefaultEncryptionParamSet"/>, and a value equal to it is
    /// omitted from the encoding, as DER requires. An encoding that includes the DEFAULT value explicitly is accepted.
    /// <para/>
    /// When the key algorithm is not known, so that the parameters could be either this structure or the GOST R
    /// 34.10-2012 one, see <see cref="Gost3410PublicKeyAlgParameters"/>.
    /// </remarks>
    public sealed class GostR3410x2001PublicKeyParameters
        : Asn1Encodable
    {
        public static readonly DerObjectIdentifier DefaultEncryptionParamSet =
            CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_A_ParamSet;

        public static GostR3410x2001PublicKeyParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GostR3410x2001PublicKeyParameters gostR3410x2001PublicKeyParameters)
                return gostR3410x2001PublicKeyParameters;
            return new GostR3410x2001PublicKeyParameters(Asn1Sequence.GetInstance(obj));
        }

        public static GostR3410x2001PublicKeyParameters GetInstance(Asn1TaggedObject taggedObject,
            bool declaredExplicit)
        {
            return new GostR3410x2001PublicKeyParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        public static GostR3410x2001PublicKeyParameters GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is GostR3410x2001PublicKeyParameters gostR3410x2001PublicKeyParameters)
                return gostR3410x2001PublicKeyParameters;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new GostR3410x2001PublicKeyParameters(asn1Sequence);

            return null;
        }

        public static GostR3410x2001PublicKeyParameters GetTagged(Asn1TaggedObject taggedObject,
            bool declaredExplicit)
        {
            return new GostR3410x2001PublicKeyParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
        }

        private readonly DerObjectIdentifier m_publicKeyParamSet;
        private readonly DerObjectIdentifier m_digestParamSet;
        private readonly DerObjectIdentifier m_encryptionParamSet;

        private GostR3410x2001PublicKeyParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_publicKeyParamSet = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_digestParamSet = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_encryptionParamSet = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional)
                ?? DefaultEncryptionParamSet;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Construct with the DEFAULT encryptionParamSet.</summary>
        public GostR3410x2001PublicKeyParameters(DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet)
            : this(publicKeyParamSet, digestParamSet, null)
        {
        }

        /// <param name="publicKeyParamSet">The public key parameter set; required.</param>
        /// <param name="digestParamSet">The digest parameter set; required.</param>
        /// <param name="encryptionParamSet">The encryption parameter set; null selects
        /// <see cref="DefaultEncryptionParamSet"/>.</param>
        public GostR3410x2001PublicKeyParameters(DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet)
        {
            m_publicKeyParamSet = publicKeyParamSet ?? throw new ArgumentNullException(nameof(publicKeyParamSet));
            m_digestParamSet = digestParamSet ?? throw new ArgumentNullException(nameof(digestParamSet));
            m_encryptionParamSet = encryptionParamSet ?? DefaultEncryptionParamSet;
        }

        public DerObjectIdentifier PublicKeyParamSet => m_publicKeyParamSet;

        public DerObjectIdentifier DigestParamSet => m_digestParamSet;

        /// <summary>The encryption parameter set; never null, since an absent value means the DEFAULT.</summary>
        public DerObjectIdentifier EncryptionParamSet => m_encryptionParamSet;

        public override Asn1Object ToAsn1Object()
        {
            return DefaultEncryptionParamSet.Equals(m_encryptionParamSet)
                ?  new DerSequence(m_publicKeyParamSet, m_digestParamSet)
                :  new DerSequence(m_publicKeyParamSet, m_digestParamSet, m_encryptionParamSet);
        }
    }
}
