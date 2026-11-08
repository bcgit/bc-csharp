using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>XMSS^MT public key (RFC 8391 sec. 4.2.5).</summary>
    public sealed class XmssMTPublicKeyParameters
        : XmssMTKeyParameters, IEncodable
    {
        private readonly XmssMTParameters m_params;
        private readonly int m_oid;
        private readonly byte[] m_root;
        private readonly byte[] m_publicSeed;

        private XmssMTPublicKeyParameters(Builder builder)
            : base(false, builder.m_params)
        {
            m_params = builder.m_params;

            // through the codec, which is where the encoding is: which of the two ways this builder was given its
            // fields decides where the parameter set identifier comes from and whether the root and the seed are
            // checked at n or read out at it.
            XmssPublicKeyCodec fields = XmssPublicKeyCodec.Resolve(builder.m_publicKey, m_params.TreeDigestSize,
                m_params.ParameterSetOid, builder.m_root, builder.m_publicSeed);

            m_oid = fields.Oid;
            m_root = fields.Root;
            m_publicSeed = fields.PublicSeed;
        }

        /// <summary>
        /// The encoding of this key: the parameter set identifier, when it has one, then root || SEED.
        /// </summary>
        public byte[] GetEncoded() => XmssPublicKeyCodec.Encode(m_oid, m_root, m_publicSeed);

        public sealed class Builder
        {
            /* mandatory */
            internal readonly XmssMTParameters m_params;
            /* optional */
            internal byte[] m_root = null;
            internal byte[] m_publicSeed = null;
            internal byte[] m_publicKey = null;

            /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
            public Builder(XmssMTParameters parameters)
            {
                m_params = parameters ?? throw new ArgumentNullException(nameof(parameters), "params == null");
            }

            public Builder WithRoot(byte[] val)
            {
                m_root = Arrays.Clone(val);
                return this;
            }

            public Builder WithPublicSeed(byte[] val)
            {
                m_publicSeed = Arrays.Clone(val);
                return this;
            }

            public Builder WithPublicKey(byte[] val)
            {
                m_publicKey = Arrays.Clone(val);
                return this;
            }

            /// <exception cref="ArgumentException">If a field, or the encoding, has the wrong size.</exception>
            public XmssMTPublicKeyParameters Build() => new XmssMTPublicKeyParameters(this);
        }

        public byte[] GetRoot() => Arrays.Clone(m_root);

        public byte[] GetPublicSeed() => Arrays.Clone(m_publicSeed);
    }
}
