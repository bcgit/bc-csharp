using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class RsaesOaepParameters
		: Asn1Encodable
	{
		public static readonly AlgorithmIdentifier DefaultHashAlgorithm = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
		public static readonly AlgorithmIdentifier DefaultMaskGenAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, DefaultHashAlgorithm);
        [Obsolete("Use 'DefaultMaskGenAlgorithm' instead")]
        public static readonly AlgorithmIdentifier DefaultMaskGenFunction = DefaultMaskGenAlgorithm;
        public static readonly AlgorithmIdentifier DefaultPSourceAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPSpecified, new DerOctetString(new byte[0]));

        public static RsaesOaepParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RsaesOaepParameters rsaesOaepParameters)
                return rsaesOaepParameters;
#pragma warning disable CS0618 // Type or member is obsolete
            return new RsaesOaepParameters(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static RsaesOaepParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RsaesOaepParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly AlgorithmIdentifier m_maskGenAlgorithm;
        private readonly AlgorithmIdentifier m_pSourceAlgorithm;

        [Obsolete("Use 'GetInstance' instead")]
        public RsaesOaepParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_hashAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, AlgorithmIdentifier.GetTagged)
				?? DefaultHashAlgorithm;

            m_maskGenAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, AlgorithmIdentifier.GetTagged)
                ?? DefaultMaskGenAlgorithm;

            m_pSourceAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, AlgorithmIdentifier.GetTagged)
                ?? DefaultPSourceAlgorithm;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
		 * The default version
		 */
        public RsaesOaepParameters()
		    : this(DefaultHashAlgorithm, DefaultMaskGenAlgorithm, DefaultPSourceAlgorithm)
		{ 
		}

        public RsaesOaepParameters(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm)
            : this(hashAlgorithm, maskGenAlgorithm, DefaultPSourceAlgorithm)
        {
        }

        public RsaesOaepParameters(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm,
            AlgorithmIdentifier pSourceAlgorithm)
        {
            m_hashAlgorithm = hashAlgorithm;
            m_maskGenAlgorithm = maskGenAlgorithm;
            m_pSourceAlgorithm = pSourceAlgorithm;
        }

		public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

		public AlgorithmIdentifier MaskGenAlgorithm => m_maskGenAlgorithm;

		public AlgorithmIdentifier PSourceAlgorithm => m_pSourceAlgorithm;

		/**
		 * <pre>
		 *  RSAES-OAEP-params ::= SEQUENCE {
		 *     hashAlgorithm      [0] OAEP-PSSDigestAlgorithms     DEFAULT sha1,
		 *     maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
		 *     pSourceAlgorithm   [2] PKCS1PSourceAlgorithms  DEFAULT pSpecifiedEmpty
		 *   }
		 *
		 *   OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
		 *     { OID id-sha1 PARAMETERS NULL   }|
		 *     { OID id-sha256 PARAMETERS NULL }|
		 *     { OID id-sha384 PARAMETERS NULL }|
		 *     { OID id-sha512 PARAMETERS NULL },
		 *     ...  -- Allows for future expansion --
		 *   }
		 *   PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
		 *     { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
		 *    ...  -- Allows for future expansion --
		 *   }
		 *   PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
		 *     { OID id-pSpecified PARAMETERS OCTET STRING },
		 *     ...  -- Allows for future expansion --
		 *  }
		 * </pre>
		 * @return the asn1 primitive representing the parameters.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);

			if (!DefaultHashAlgorithm.Equals(m_hashAlgorithm))
			{
				v.Add(new DerTaggedObject(true, 0, m_hashAlgorithm));
			}

			if (!DefaultMaskGenAlgorithm.Equals(m_maskGenAlgorithm))
			{
				v.Add(new DerTaggedObject(true, 1, m_maskGenAlgorithm));
			}

			if (!DefaultPSourceAlgorithm.Equals(m_pSourceAlgorithm))
			{
				v.Add(new DerTaggedObject(true, 2, m_pSourceAlgorithm));
			}

			return new DerSequence(v);
		}
	}
}
