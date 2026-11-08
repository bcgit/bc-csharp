using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * XMSSMTPrivateKey, the private key of the legacy key encodings.
     * <pre>
     *     XMSSMTPrivateKey ::= SEQUENCE {
     *         version INTEGER -- 0, or 1 if maxIndex is present
     *         keyData SEQUENCE {
     *            index         INTEGER
     *            secretKeySeed OCTET STRING
     *            secretKeyPRF  OCTET STRING
     *            publicSeed    OCTET STRING
     *            root          OCTET STRING
     *            maxIndex      [0] INTEGER OPTIONAL
     *         }
     *         bdsState CHOICE {
     *             legacyBdsState [0] OCTET STRING,
     *             binaryBdsState [1] OCTET STRING
     *         } OPTIONAL
     *             -- opaque, implementation-specific traversal state. [0] carries the
     *             -- legacy Java serialization, [1] the versioned binary BDS state map.
     *    }
     * </pre>
     * The secret key seed and PRF key are held as copies; the arrays this hands out are copies of those.
     */
    public sealed class XmssMTPrivateKey
        : Asn1Encodable
    {
        private const int LegacyBdsState = 0;
        private const int BinaryBdsState = 1;

        public static XmssMTPrivateKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is XmssMTPrivateKey privateKey)
                return privateKey;
            return new XmssMTPrivateKey(Asn1Sequence.GetInstance(obj));
        }

        public static XmssMTPrivateKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssMTPrivateKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static XmssMTPrivateKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssMTPrivateKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly int m_version;
        private readonly long m_index;
        private readonly byte[] m_secretKeySeed;
        private readonly byte[] m_secretKeyPrf;
        private readonly byte[] m_publicSeed;
        private readonly byte[] m_root;
        private readonly long m_maxIndex;
        private readonly byte[] m_bdsState;
        private readonly int m_bdsStateTag;

        /// <summary>
        /// A key without a maximum index. <paramref name="bdsState"/>, if present, is written in the binary [1]
        /// alternative; the legacy Java serialization is accepted on parsing but is no longer generated.
        /// </summary>
        public XmssMTPrivateKey(long index, byte[] secretKeySeed, byte[] secretKeyPrf, byte[] publicSeed, byte[] root,
            byte[] bdsState)
            : this(0, index, secretKeySeed, secretKeyPrf, publicSeed, root, bdsState, -1)
        {
        }

        /// <summary>
        /// A key carrying a maximum index. <paramref name="bdsState"/>, if present, is written in the binary [1]
        /// alternative; the legacy Java serialization is accepted on parsing but is no longer generated.
        /// </summary>
        public XmssMTPrivateKey(long index, byte[] secretKeySeed, byte[] secretKeyPrf, byte[] publicSeed, byte[] root,
            byte[] bdsState, long maxIndex)
            : this(1, index, secretKeySeed, secretKeyPrf, publicSeed, root, bdsState, maxIndex)
        {
            // a negative one would be written as a key without one, at version 0
            if (maxIndex < 0)
                throw new ArgumentException("maxIndex must not be negative", nameof(maxIndex));
        }

        private XmssMTPrivateKey(int version, long index, byte[] secretKeySeed, byte[] secretKeyPrf, byte[] publicSeed,
            byte[] root, byte[] bdsState, long maxIndex)
        {
            m_version = version;
            m_bdsStateTag = BinaryBdsState;
            m_index = index;
            m_secretKeySeed = Arrays.Clone(secretKeySeed ?? throw new ArgumentNullException(nameof(secretKeySeed)));
            m_secretKeyPrf = Arrays.Clone(secretKeyPrf ?? throw new ArgumentNullException(nameof(secretKeyPrf)));
            m_publicSeed = Arrays.Clone(publicSeed ?? throw new ArgumentNullException(nameof(publicSeed)));
            m_root = Arrays.Clone(root ?? throw new ArgumentNullException(nameof(root)));
            m_bdsState = Arrays.Clone(bdsState);
            m_maxIndex = maxIndex;
        }

        private XmssMTPrivateKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2 && count != 3)
                throw new ArgumentException("key sequence wrong size");

            DerInteger v = DerInteger.GetInstance(seq[0]);
            if (!(v.HasValue(0) || v.HasValue(1)))
                throw new ArgumentException("unknown version of sequence");

            m_version = v.IntValueExact;

            Asn1Sequence keySeq = Asn1Sequence.GetInstance(seq[1]);
            int keyCount = keySeq.Count;
            if (keyCount != 5 && keyCount != 6)
                throw new ArgumentException("keySeq should be 5 or 6 in length");

            m_index = DerInteger.GetInstance(keySeq[0]).LongValueExact;
            m_secretKeySeed = Arrays.Clone(Asn1OctetString.GetInstance(keySeq[1]).GetOctets());
            m_secretKeyPrf = Arrays.Clone(Asn1OctetString.GetInstance(keySeq[2]).GetOctets());
            m_publicSeed = Arrays.Clone(Asn1OctetString.GetInstance(keySeq[3]).GetOctets());
            m_root = Arrays.Clone(Asn1OctetString.GetInstance(keySeq[4]).GetOctets());

            if (keyCount == 6)
            {
                Asn1TaggedObject tagged = Asn1TaggedObject.GetInstance(keySeq[5]);
                if (tagged.TagNo != 0)
                    throw new ArgumentException("unknown tag in XMSSMTPrivateKey");

                m_maxIndex = DerInteger.GetInstance(tagged, false).LongValueExact;
            }
            else
            {
                // version 1 is the version that carries [0]: one without it would be written back as version 0
                if (m_version == 1)
                    throw new ArgumentException("version 1 key without maxIndex");

                m_maxIndex = -1;
            }

            if (count == 3)
            {
                Asn1TaggedObject state = Asn1TaggedObject.GetInstance(seq[2]);
                if (state.TagNo != LegacyBdsState && state.TagNo != BinaryBdsState)
                    throw new ArgumentException("unknown bdsState choice in XMSSMTPrivateKey");

                m_bdsStateTag = state.TagNo;
                m_bdsState = Arrays.Clone(Asn1OctetString.GetInstance(state, true).GetOctets());
            }
            else
            {
                m_bdsStateTag = LegacyBdsState;
                m_bdsState = null;
            }
        }

        public int Version => m_version;

        public long Index => m_index;

        /// <summary>The maximum index, or -1 if the key does not carry one.</summary>
        public long MaxIndex => m_maxIndex;

        public byte[] GetSecretKeySeed() => Arrays.Clone(m_secretKeySeed);

        public byte[] GetSecretKeyPrf() => Arrays.Clone(m_secretKeyPrf);

        public byte[] GetPublicSeed() => Arrays.Clone(m_publicSeed);

        public byte[] GetRoot() => Arrays.Clone(m_root);

        /// <summary>The encoded traversal state, or null if the key carries none.</summary>
        public byte[] GetBdsState() => Arrays.Clone(m_bdsState);

        /// <summary>
        /// Whether the traversal state was carried in the versioned binary alternative ([1]) rather than the legacy
        /// Java serialization alternative ([0]).
        /// </summary>
        public bool HasBinaryBdsState => m_bdsStateTag == BinaryBdsState;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);

            v.Add(m_maxIndex >= 0 ? DerInteger.One : DerInteger.Zero);

            Asn1EncodableVector vK = new Asn1EncodableVector(6);
            vK.Add(DerInteger.ValueOf(m_index));
            vK.Add(new DerOctetString(m_secretKeySeed));
            vK.Add(new DerOctetString(m_secretKeyPrf));
            vK.Add(new DerOctetString(m_publicSeed));
            vK.Add(new DerOctetString(m_root));
            if (m_maxIndex >= 0)
            {
                vK.Add(new DerTaggedObject(false, 0, DerInteger.ValueOf(m_maxIndex)));
            }
            v.Add(new DerSequence(vK));

            if (m_bdsState != null)
            {
                v.Add(new DerTaggedObject(true, m_bdsStateTag, new DerOctetString(m_bdsState)));
            }

            return new DerSequence(v);
        }
    }
}
