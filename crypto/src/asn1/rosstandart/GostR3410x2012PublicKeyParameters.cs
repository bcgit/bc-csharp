using System;

using Org.BouncyCastle.Asn1.CryptoPro;

namespace Org.BouncyCastle.Asn1.Rosstandart
{
    /// <summary>
    /// The AlgorithmIdentifier parameters for GOST R 34.10-2012 keys (RFC 9215, Section 4.2).
    /// </summary>
    /// <remarks>
    /// <code>
    /// GostR3410-2012-PublicKeyParameters ::= SEQUENCE {
    ///     publicKeyParamSet   OBJECT IDENTIFIER,
    ///     digestParamSet      OBJECT IDENTIFIER OPTIONAL
    /// }
    /// </code>
    /// Unlike the GOST R 34.10-2001 structure, there is no encryptionParamSet. RFC 9215 also constrains when
    /// digestParamSet must or should be omitted, depending on publicKeyParamSet; those value-level rules are not
    /// enforced here.
    /// <para/>
    /// When the key algorithm is not known, so that the parameters could be either this structure or the GOST R
    /// 34.10-2001 one, see <see cref="Gost3410PublicKeyAlgParameters"/>.
    /// </remarks>
    public class GostR3410x2012PublicKeyParameters
        : Asn1Encodable
    {
        public static GostR3410x2012PublicKeyParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GostR3410x2012PublicKeyParameters gostR3410x2012PublicKeyParameters)
                return gostR3410x2012PublicKeyParameters;
            return new GostR3410x2012PublicKeyParameters(Asn1Sequence.GetInstance(obj));
        }

        public static GostR3410x2012PublicKeyParameters GetInstance(Asn1TaggedObject taggedObject,
            bool declaredExplicit)
        {
            return new GostR3410x2012PublicKeyParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        public static GostR3410x2012PublicKeyParameters GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is GostR3410x2012PublicKeyParameters gostR3410x2012PublicKeyParameters)
                return gostR3410x2012PublicKeyParameters;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new GostR3410x2012PublicKeyParameters(asn1Sequence);

            return null;
        }

        public static GostR3410x2012PublicKeyParameters GetTagged(Asn1TaggedObject taggedObject,
            bool declaredExplicit)
        {
            return new GostR3410x2012PublicKeyParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
        }

        private readonly DerObjectIdentifier m_publicKeyParamSet;
        private readonly DerObjectIdentifier m_digestParamSet;

        private GostR3410x2012PublicKeyParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_publicKeyParamSet = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_digestParamSet = Asn1Utilities.ReadOptional(seq, ref pos, DerObjectIdentifier.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Construct with digestParamSet omitted.</summary>
        public GostR3410x2012PublicKeyParameters(DerObjectIdentifier publicKeyParamSet)
            : this(publicKeyParamSet, null)
        {
        }

        /// <param name="publicKeyParamSet">The public key parameter set; required.</param>
        /// <param name="digestParamSet">The digest parameter set; may be null (omitted).</param>
        public GostR3410x2012PublicKeyParameters(DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet)
        {
            m_publicKeyParamSet = publicKeyParamSet ?? throw new ArgumentNullException(nameof(publicKeyParamSet));
            m_digestParamSet = digestParamSet;
        }

        public DerObjectIdentifier PublicKeyParamSet => m_publicKeyParamSet;

        /// <summary>The digest parameter set, or null if omitted.</summary>
        public DerObjectIdentifier DigestParamSet => m_digestParamSet;

        public override Asn1Object ToAsn1Object()
        {
            return m_digestParamSet == null
                ?  new DerSequence(m_publicKeyParamSet)
                :  new DerSequence(m_publicKeyParamSet, m_digestParamSet);
        }
    }
}
