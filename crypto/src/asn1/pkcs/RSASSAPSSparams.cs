using System;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The RSASSA-PSS-params structure of PKCS#1.</summary>
    public class RsassaPssParameters
        : Asn1Encodable
    {
        public readonly static AlgorithmIdentifier DefaultHashAlgorithm = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
        public readonly static AlgorithmIdentifier DefaultMaskGenAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, DefaultHashAlgorithm);
        [Obsolete("Use 'DefaultMaskGenAlgorithm' instead")]
        public readonly static AlgorithmIdentifier DefaultMaskGenFunction = DefaultMaskGenAlgorithm;
        public readonly static DerInteger DefaultSaltLength = DerInteger.ValueOf(20);
        public readonly static DerInteger DefaultTrailerField = DerInteger.One;

        /// <summary>Return an <see cref="RsassaPssParameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RsassaPssParameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RsassaPssParameters"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RsassaPssParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RsassaPssParameters rsassaPssParameters)
                return rsassaPssParameters;
#pragma warning disable CS0618 // Type or member is obsolete
            return new RsassaPssParameters(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="RsassaPssParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsassaPssParameters"/>.</returns>
        public static RsassaPssParameters GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RsassaPssParameters(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="RsassaPssParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsassaPssParameters"/>.</returns>
        public static RsassaPssParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RsassaPssParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly AlgorithmIdentifier m_maskGenAlgorithm;
        private readonly DerInteger m_saltLength;
        private readonly DerInteger m_trailerField;

        /// <summary>Create a new <see cref="RsassaPssParameters"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public RsassaPssParameters(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 0 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, AlgorithmIdentifier.GetTagged)
                ?? DefaultHashAlgorithm;

            m_maskGenAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, AlgorithmIdentifier.GetTagged)
                ?? DefaultMaskGenAlgorithm;

            m_saltLength = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, DerInteger.GetTagged)
                ?? DefaultSaltLength;

            m_trailerField = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, true, DerInteger.GetTagged)
                ?? DefaultTrailerField;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
         * The default version
         */
        public RsassaPssParameters()
        {
            m_hashAlgorithm = DefaultHashAlgorithm;
            m_maskGenAlgorithm = DefaultMaskGenAlgorithm;
            m_saltLength = DefaultSaltLength;
            m_trailerField = DefaultTrailerField;
        }

        /// <summary>Create a new <see cref="RsassaPssParameters"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="maskGenAlgorithm">The mask gen algorithm.</param>
        /// <param name="saltLength">The salt length.</param>
        /// <param name="trailerField">The trailer field.</param>
        public RsassaPssParameters(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm,
            DerInteger saltLength, DerInteger trailerField)
        {
            m_hashAlgorithm = hashAlgorithm ?? DefaultHashAlgorithm;
            m_maskGenAlgorithm = maskGenAlgorithm ?? DefaultMaskGenAlgorithm;
            m_saltLength = saltLength ?? DefaultSaltLength;
            m_trailerField = trailerField ?? DefaultTrailerField;
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Gets the mask gen algorithm.</summary>
        public AlgorithmIdentifier MaskGenAlgorithm => m_maskGenAlgorithm;

        /// <summary>Gets the salt length.</summary>
        public DerInteger SaltLength => m_saltLength;

        /// <summary>Gets the trailer field.</summary>
        public DerInteger TrailerField => m_trailerField;

        /**
         * <pre>
         * RSASSA-PSS-params ::= SEQUENCE {
         *   hashAlgorithm      [0] OAEP-PSSDigestAlgorithms  DEFAULT sha1,
         *    maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
         *    saltLength         [2] INTEGER  DEFAULT 20,
         *    trailerField       [3] TrailerField  DEFAULT trailerFieldBC
         *  }
         *
         * OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
         *    { OID id-sha1 PARAMETERS NULL   }|
         *    { OID id-sha256 PARAMETERS NULL }|
         *    { OID id-sha384 PARAMETERS NULL }|
         *    { OID id-sha512 PARAMETERS NULL },
         *    ...  -- Allows for future expansion --
         * }
         *
         * PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
         *   { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
         *    ...  -- Allows for future expansion --
         * }
         *
         * TrailerField ::= INTEGER { trailerFieldBC(1) }
         * </pre>
         * @return the asn1 primitive representing the parameters.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);

            if (!DefaultHashAlgorithm.Equals(m_hashAlgorithm))
            {
                v.Add(new DerTaggedObject(true, 0, m_hashAlgorithm));
            }

            if (!DefaultMaskGenAlgorithm.Equals(m_maskGenAlgorithm))
            {
                v.Add(new DerTaggedObject(true, 1, m_maskGenAlgorithm));
            }

            if (!DefaultSaltLength.Equals(m_saltLength))
            {
                v.Add(new DerTaggedObject(true, 2, m_saltLength));
            }

            if (!DefaultTrailerField.Equals(m_trailerField))
            {
                v.Add(new DerTaggedObject(true, 3, m_trailerField));
            }

            return new DerSequence(v);
        }
    }
}
