using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * See https://datatracker.ietf.org/doc/draft-uni-qsckeys-sphincsplus/00/ for details
     * ASN.1 Encoding for a
     * SphincsPlus private key for fully populated:
     * <pre>
     *   SPHINCSPLUSPrivateKey ::= SEQUENCE {
     *     version          INTEGER {v2(1)}     --syntax version 2 (round 3)
     *     skseed          OCTET STRING,        --n-byte private key seed
     *     skprf           OCTET STRING,        --n-byte private key seed
     *     PublicKey       SPHINCSPLUSPublicKey --public key
     *   }
     * </pre>
     */
    [Obsolete("Use SLH-DSA instead")]
    public sealed class SphincsPlusPrivateKey
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SphincsPlusPrivateKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SphincsPlusPrivateKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SphincsPlusPrivateKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SphincsPlusPrivateKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SphincsPlusPrivateKey sphincsPlusPrivateKey)
                return sphincsPlusPrivateKey;
            return new SphincsPlusPrivateKey(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="SphincsPlusPrivateKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SphincsPlusPrivateKey"/>.</returns>
        public static SphincsPlusPrivateKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPrivateKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SphincsPlusPrivateKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SphincsPlusPrivateKey"/>.</returns>
        public static SphincsPlusPrivateKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPrivateKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        /// <summary>Create a new <see cref="SphincsPlusPrivateKey"/>.</summary>
        /// <param name="version">The version.</param>
        /// <param name="skseed">The skseed.</param>
        /// <param name="skprf">The skprf.</param>
        public SphincsPlusPrivateKey(int version, byte[] skseed, byte[] skprf)
            : this(version, skseed, skprf, null)
        {
        }

        private readonly DerInteger m_version;
        private readonly Asn1OctetString m_skseed;
        private readonly Asn1OctetString m_skprf;
        private readonly SphincsPlusPublicKey m_publicKey;

        /// <summary>Create a new <see cref="SphincsPlusPrivateKey"/>.</summary>
        /// <param name="version">The version.</param>
        /// <param name="skseed">The skseed.</param>
        /// <param name="skprf">The skprf.</param>
        /// <param name="publicKey">The public key.</param>
        public SphincsPlusPrivateKey(int version, byte[] skseed, byte[] skprf, SphincsPlusPublicKey publicKey)
        {
            m_version = DerInteger.ValueOf(version);
            m_skseed = DerOctetString.FromContents(skseed);
            m_skprf = DerOctetString.FromContents(skprf);
            m_publicKey = publicKey;
        }

        private SphincsPlusPrivateKey(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_skseed = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_skprf = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_publicKey = Asn1Utilities.ReadOptional(seq, ref pos, SphincsPlusPublicKey.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!m_version.HasValue(0))
                throw new Exception("unrecognized version");
        }

        /// <summary>Return the skprf.</summary>
        public byte[] GetSkprf() => Arrays.Clone(m_skprf.GetOctets());

        /// <summary>Return the skseed.</summary>
        public byte[] GetSkseed() => Arrays.Clone(m_skseed.GetOctets());

        public SphincsPlusPublicKey PublicKey => m_publicKey;

        /// <summary>Gets the version.</summary>
        public int Version => m_version.IntValueExact;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_version, m_skseed, m_skprf);
            v.AddOptional(m_publicKey);
            return new DerSequence(v);
        }
    }
}
