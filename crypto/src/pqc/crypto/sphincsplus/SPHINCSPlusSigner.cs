using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    /**
     * SPHINCS+ signer.
     * <p>
     *     This version is based on the 3rd submission with deference to the updated reference
     *     implementation on github as at November 9th 2021. This version includes the changes
     *     for the countermeasure for the long-message second preimage attack - see
     *     "https://github.com/sphincs/sphincsplus/commit/61cd2695c6f984b4f4d6ed675378ed9a486cbede"
     *     for further details.
     * </p>
     */
    public sealed class SphincsPlusSigner
        : IMessageSigner
    {
        private SphincsPlusPrivateKeyParameters m_privKey;
        private SphincsPlusPublicKeyParameters m_pubKey;

        private SecureRandom m_random;

        /**
         * Base constructor.
         */
        public SphincsPlusSigner()
        {
        }

        public void Init(bool forSigning, ICipherParameters param)
        {
            if (forSigning)
            {
                m_pubKey = null;
                if (param is ParametersWithRandom withRandom)
                {
                    m_privKey = (SphincsPlusPrivateKeyParameters)withRandom.Parameters;
                    m_random = withRandom.Random;
                }
                else
                {
                    m_privKey = (SphincsPlusPrivateKeyParameters)param;
                    m_random = null;
                }
            }
            else
            {
                m_pubKey = (SphincsPlusPublicKeyParameters)param;
                m_privKey = null;
                m_random = null;
            }
        }

        public byte[] GenerateSignature(byte[] message)
        {
            // # Input: Message M, private key SK = (SK.seed, SK.prf, PK.seed, PK.root)
            // # Output: SPHINCS+ signature SIG
            // init

            SphincsPlusEngine engine = m_privKey.Parameters.GetEngine();
            engine.Init(m_privKey.GetPublicSeed());
            // generate randomizer
            byte[] optRand = new byte[engine.N];
            if (m_random != null)
            {
                m_random.NextBytes(optRand);
            }
            else
            {
                Array.Copy(m_privKey.m_pk.seed, 0, optRand, 0, optRand.Length);
            }

            Fors fors = new Fors(engine);
            byte[] R = engine.PRF_msg(m_privKey.m_sk.prf, optRand, message);
            // compute message digest and index
            IndexedDigest idxDigest = engine.H_msg(R, m_privKey.m_pk.seed, m_privKey.m_pk.root, message);
            byte[] mHash = idxDigest.digest;
            ulong idx_tree = idxDigest.idx_tree;
            uint idx_leaf = idxDigest.idx_leaf;
            // FORS sign
            Adrs adrs = new Adrs();
            adrs.SetAdrsType(Adrs.FORS_TREE);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);
            SIG_FORS[] sig_fors = fors.Sign(mHash, m_privKey.m_sk.seed, m_privKey.m_pk.seed, adrs);
            // get FORS public key - spec shows M?
            adrs = new Adrs();
            adrs.SetAdrsType(Adrs.FORS_TREE);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);

            byte[] PK_FORS = fors.PKFromSig(sig_fors, mHash, m_privKey.m_pk.seed, adrs);

            // sign FORS public key with HT
            Adrs treeAdrs = new Adrs();
            treeAdrs.SetAdrsType(Adrs.TREE);

            HT ht = new HT(engine, m_privKey.GetSeed(), m_privKey.GetPublicSeed());
            byte[] SIG_HT = ht.Sign(PK_FORS, idx_tree, idx_leaf);
            byte[][] sigComponents = new byte[sig_fors.Length + 2][];
            sigComponents[0] = R;

            for (int i = 0; i != sig_fors.Length; i++)
            {
                sigComponents[1 + i] = Arrays.Concatenate(sig_fors[i].sk, Arrays.ConcatenateAll(sig_fors[i].authPath));
            }

            sigComponents[sigComponents.Length - 1] = SIG_HT;

            return Arrays.ConcatenateAll(sigComponents);
        }

        public bool VerifySignature(byte[] message, byte[] signature)
        {
            //# Input: Message M, signature SIG, public key PK
            //# Output: bool

            // init
            SphincsPlusEngine engine = m_pubKey.Parameters.GetEngine();
            engine.Init(m_pubKey.GetSeed());

            Adrs adrs = new Adrs();
            SIG sig = new SIG(engine.N, engine.K, engine.A, engine.D, engine.H_PRIME, engine.WOTS_LEN, signature);

            byte[] R = sig.R;
            SIG_FORS[] sig_fors = sig.SIG_FORS;
            SIG_XMSS[] SIG_HT = sig.SIG_HT;

            // compute message digest and index
            IndexedDigest idxDigest = engine.H_msg(R, m_pubKey.GetSeed(), m_pubKey.GetRoot(), message);
            byte[] mHash = idxDigest.digest;
            ulong idx_tree = idxDigest.idx_tree;
            uint idx_leaf = idxDigest.idx_leaf;

            // compute FORS public key
            adrs.SetAdrsType(Adrs.FORS_TREE);
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);
            byte[] PK_FORS = new Fors(engine).PKFromSig(sig_fors, mHash, m_pubKey.GetSeed(), adrs);
            // verify HT signature
            adrs.SetAdrsType(Adrs.TREE);
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);
            adrs.SetKeyPairAddress(idx_leaf);
            HT ht = new HT(engine, null, m_pubKey.GetSeed());
            return ht.Verify(PK_FORS, SIG_HT, m_pubKey.GetSeed(), idx_tree, idx_leaf, m_pubKey.GetRoot());
        }
    }
}
