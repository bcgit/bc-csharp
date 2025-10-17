using System;

using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaPublicKeyParameters
        : SlhDsaKeyParameters
    {
        public static SlhDsaPublicKeyParameters FromEncoding(SlhDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PublicKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            int n = parameters.ParameterSet.N;
            PK pk = new PK(Arrays.CopyOfRange(encoding, 0, n), Arrays.CopyOfRange(encoding, n, 2 * n));
            return new SlhDsaPublicKeyParameters(parameters, pk);
        }

        private readonly PK m_pk;

        internal SlhDsaPublicKeyParameters(SlhDsaParameters parameters, PK pk)
            : base(false, parameters)
        {
            m_pk = pk;
        }

        public byte[] GetEncoded() => Arrays.Concatenate(m_pk.seed, m_pk.root);

        internal PK PK => m_pk;

        internal bool VerifyInternal(byte[] msg, int msgOff, int msgLen, byte[] signature)
        {
            //# Input: Message M, signature SIG, public key PK
            //# Output: bool

            var engine = Parameters.ParameterSet.GetEngine();

            if (engine.SignatureLength != signature.Length)
                return false;

            // init
            engine.Init(PK.seed);

            Adrs adrs = new Adrs();
            SIG sig = new SIG(engine, signature);

            byte[] R = sig.R;
            SIG_FORS[] sig_fors = sig.SIG_FORS;
            SIG_XMSS[] SIG_HT = sig.SIG_HT;

            // compute message digest and index
            IndexedDigest idxDigest = engine.H_msg(R, 0, PK.seed, PK.root, msg, msgOff, msgLen);
            byte[] mHash = idxDigest.digest;
            ulong idx_tree = idxDigest.idx_tree;
            uint idx_leaf = idxDigest.idx_leaf;

            // compute FORS public key
            adrs.SetTypeAndClear(Adrs.FORS_TREE);
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);

            byte[] PK_FORS = Fors.PKFromSig(engine, sig_fors, mHash, PK.seed, adrs, legacy: false);

            // verify HT signature
            adrs.SetTypeAndClear(Adrs.TREE);
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);
            HT ht = new HT(engine, null, PK.seed);
            return ht.Verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root);
        }
    }
}
