using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The RSAES-OAEP-params structure of PKCS#1.</summary>
    public class RsaesOaepParameters
        : Asn1Encodable
    {
        /// <summary>The default hash algorithm, SHA-1.</summary>
        public static readonly AlgorithmIdentifier DefaultHashAlgorithm = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
        /// <summary>The default mask generation algorithm, MGF1 with SHA-1.</summary>
        public static readonly AlgorithmIdentifier DefaultMaskGenAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, DefaultHashAlgorithm);
        /// <summary>The default mask generation function, MGF1 with SHA-1.</summary>
        [Obsolete("Use 'DefaultMaskGenAlgorithm' instead")]
        public static readonly AlgorithmIdentifier DefaultMaskGenFunction = DefaultMaskGenAlgorithm;
        /// <summary>The default source of the encoding parameters, an empty string.</summary>
        public static readonly AlgorithmIdentifier DefaultPSourceAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPSpecified, DerOctetString.Empty);

        /// <summary>Return an <see cref="RsaesOaepParameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RsaesOaepParameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RsaesOaepParameters"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="RsaesOaepParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsaesOaepParameters"/>.</returns>
        public static RsaesOaepParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RsaesOaepParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="RsaesOaepParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsaesOaepParameters"/>.</returns>
        public static RsaesOaepParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RsaesOaepParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly AlgorithmIdentifier m_maskGenAlgorithm;
        private readonly AlgorithmIdentifier m_pSourceAlgorithm;

        /// <summary>Create a new <see cref="RsaesOaepParameters"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public RsaesOaepParameters(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

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

        /// <summary>Create a new <see cref="RsaesOaepParameters"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="maskGenAlgorithm">The mask gen algorithm.</param>
        public RsaesOaepParameters(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm)
            : this(hashAlgorithm, maskGenAlgorithm, DefaultPSourceAlgorithm)
        {
        }

        /// <summary>Create a new <see cref="RsaesOaepParameters"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="maskGenAlgorithm">The mask gen algorithm.</param>
        /// <param name="pSourceAlgorithm">The p source algorithm.</param>
        public RsaesOaepParameters(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm,
            AlgorithmIdentifier pSourceAlgorithm)
        {
            m_hashAlgorithm = hashAlgorithm;
            m_maskGenAlgorithm = maskGenAlgorithm;
            m_pSourceAlgorithm = pSourceAlgorithm;
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Gets the mask gen algorithm.</summary>
        public AlgorithmIdentifier MaskGenAlgorithm => m_maskGenAlgorithm;

        /// <summary>Gets the p source algorithm.</summary>
        public AlgorithmIdentifier PSourceAlgorithm => m_pSourceAlgorithm;

        /// <summary>Return a copy of these parameters with the default source of the encoding parameters.</summary>
        /// <returns>The new parameters.</returns>
        public RsaesOaepParameters WithDefaultPSource()
        {
            if (DefaultPSourceAlgorithm == m_pSourceAlgorithm)
                return this;

            return new RsaesOaepParameters(m_hashAlgorithm, m_maskGenAlgorithm, DefaultPSourceAlgorithm);
        }

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

            return DerSequence.FromVector(v);
        }
    }
}
