using System;

using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class SlhDsaPublicKeyParameters
        : SlhDsaKeyParameters
    {
        private readonly PK m_pk;

        public SlhDsaPublicKeyParameters(SlhDsaParameters parameters, byte[] encoding)
            : base(false, parameters)
        {
            int n = parameters.N;
            if (encoding.Length != 2 * n)
                throw new ArgumentException("public key encoding does not match parameters", nameof(encoding));

            m_pk = new PK(Arrays.CopyOfRange(encoding, 0, n), Arrays.CopyOfRange(encoding, n, 2 * n));
        }

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

            var engine = Parameters.GetEngine();

            if (engine.SignatureLength != signature.Length)
                return false;

            // init
            engine.Init(PK.seed);

            Adrs adrs = new Adrs();
            SIG sig = new SIG(engine.N, engine.K, engine.A, engine.D, engine.H_PRIME, engine.WOTS_LEN, signature);

            byte[] R = sig.R;
            SIG_FORS[] sig_fors = sig.SIG_FORS;
            SIG_XMSS[] SIG_HT = sig.SIG_HT;

            // compute message digest and index
            IndexedDigest idxDigest = engine.H_msg(R, PK.seed, PK.root, msg, msgOff, msgLen);
            byte[] mHash = idxDigest.digest;
            ulong idx_tree = idxDigest.idx_tree;
            uint idx_leaf = idxDigest.idx_leaf;

            // compute FORS public key
            adrs.SetTypeAndClear(Adrs.FORS_TREE);
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);
            byte[] PK_FORS = new Fors(engine).PKFromSig(sig_fors, mHash, PK.seed, adrs, legacy: false);

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
