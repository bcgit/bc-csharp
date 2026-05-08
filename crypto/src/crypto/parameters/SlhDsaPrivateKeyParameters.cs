using System;

using Org.BouncyCastle.Crypto.Signers.SlhDsa;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// SLH-DSA private key (FIPS 205). Holds the (SK.seed, SK.prf, PK.seed, PK.root) tuple — the
    /// signing seed and PRF key together with a copy of the public key needed for hypertree
    /// verification during signing.
    /// </summary>
    public sealed class SlhDsaPrivateKeyParameters
        : SlhDsaKeyParameters
    {
        /// <summary>
        /// Decode a private key from its concatenated <c>SK.seed || SK.prf || PK.seed || PK.root</c>
        /// byte representation. The expected length is <c>4 * n</c> for the chosen parameter set.
        /// </summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or
        /// <paramref name="encoding"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="encoding"/> length does not match the
        /// parameter set's private-key length.</exception>
        public static SlhDsaPrivateKeyParameters FromEncoding(SlhDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PrivateKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            int n = parameters.ParameterSet.N;
            SK sk = new SK(Arrays.CopyOfRange(encoding, 0, n), Arrays.CopyOfRange(encoding, n, 2 * n));
            PK pk = new PK(Arrays.CopyOfRange(encoding, 2 * n, 3 * n), Arrays.CopyOfRange(encoding, 3 * n, 4 * n));
            return new SlhDsaPrivateKeyParameters(parameters, sk, pk);
        }

        private readonly SK m_sk;
        private readonly PK m_pk;

        internal SlhDsaPrivateKeyParameters(SlhDsaParameters parameters, SK sk, PK pk)
            : base(true, parameters)
        {
            m_sk = sk;
            m_pk = pk;
        }

        /// <summary>
        /// Return a fresh copy of the concatenated <c>SK.seed || SK.prf || PK.seed || PK.root</c>
        /// encoding.
        /// </summary>
        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_sk.Seed, m_sk.Prf, m_pk.Seed, m_pk.Root);

        /// <summary>Return the public key embedded in this private key.</summary>
        public SlhDsaPublicKeyParameters GetPublicKey() => new SlhDsaPublicKeyParameters(Parameters, m_pk);

        /// <summary>Return a fresh copy of the public key portion (<c>seed || root</c>).</summary>
        public byte[] GetPublicKeyEncoded() => Arrays.Concatenate(m_pk.Seed, m_pk.Root);

        internal PK PK => m_pk;

        internal SK SK => m_sk;

        internal byte[] SignInternal(byte[] optRand, byte[] msg, int msgOff, int msgLen)
        {
            var engine = Parameters.ParameterSet.GetEngine();

            if (optRand == null)
            {
                optRand = Arrays.CopyOfRange(PK.Seed, 0, engine.N);
            }
            else if (optRand.Length != engine.N)
            {
                throw new ArgumentOutOfRangeException(nameof(optRand));
            }

            engine.Init(PK.Seed);

            byte[] signature = new byte[engine.SignatureLength];
            engine.PrfMsg(SK.Prf, optRand, msg, msgOff, msgLen, signature, 0);

            // compute message digest and index
            IndexedDigest idxDigest = engine.HMsg(signature, 0, PK.Seed, PK.Root, msg, msgOff, msgLen);

            byte[] digest = idxDigest.Digest;
            ulong idxTree = idxDigest.IdxTree;
            uint idxLeaf = idxDigest.IdxLeaf;

            // FORS sign
            Adrs adrs = new Adrs(Adrs.ForsTree);
            adrs.SetTreeAddress(idxTree);
            adrs.SetKeyPairAddress(idxLeaf);

            Fors.Sign(engine, digest, SK.Seed, adrs, signature);

            // get FORS public key - spec shows M?
            adrs = new Adrs(Adrs.ForsTree);
            adrs.SetTreeAddress(idxTree);
            adrs.SetKeyPairAddress(idxLeaf);

            byte[] PK_FORS = new byte[engine.N];
            Fors.PKFromSig(engine, signature, digest, adrs, PK_FORS, 0);

            // sign FORS public key with HT
            Adrs treeAdrs = new Adrs(Adrs.Tree);

            HT ht = new HT(engine, SK.Seed, PK.Seed);
            ht.Sign(PK_FORS, idxTree, idxLeaf, signature);

            return signature;
        }
    }
}
