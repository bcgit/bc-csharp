using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class HT
    {
        private byte[] skSeed;
        private byte[] pkSeed;
        SphincsPlusEngine engine;
        WotsPlus wots;

        internal byte[] HTPubKey;

        internal HT(SphincsPlusEngine engine, byte[] skSeed, byte[] pkSeed)
        {
            this.skSeed = skSeed;
            this.pkSeed = pkSeed;

            this.engine = engine;
            this.wots = new WotsPlus(engine);

            Adrs adrs = new Adrs();
            adrs.SetLayerAddress(engine.D - 1);
            adrs.SetTreeAddress(0);

            if (skSeed != null)
            {
                HTPubKey = xmss_PKgen(skSeed, pkSeed, adrs);
            }
            else
            {
                HTPubKey = null;
            }
        }

        internal int GetSignatureLength() => (int)engine.D * (engine.WOTS_LEN + (int)engine.H_PRIME) * engine.N;

        internal void Sign(byte[] M, ulong idx_tree, uint idx_leaf, byte[] signature, ref int pos)
        {
            // init
            Adrs adrs = new Adrs();
            // sign
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);
            SIG_XMSS SIG_tmp = xmss_sign(M, skSeed, idx_leaf, pkSeed, adrs);
            SIG_XMSS[] SIG_HT = new SIG_XMSS[engine.D];
            SIG_HT[0] = SIG_tmp;

            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);

            byte[] root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, pkSeed, adrs);

            for (uint j = 1; j < engine.D; j++)
            {
                idx_leaf = (uint) (idx_tree & (ulong)((1 << (int)engine.H_PRIME) - 1)); // least significant bits of idx_tree; //todo might be not working as inteded
                idx_tree >>= (int)engine.H_PRIME; // most significant bits of idx_tree;
                adrs.SetLayerAddress(j);
                adrs.SetTreeAddress(idx_tree);
                SIG_tmp = xmss_sign(root, skSeed, idx_leaf, pkSeed, adrs);
                SIG_HT[j] = SIG_tmp;
                if (j < engine.D - 1)
                {
                    root = xmss_pkFromSig(idx_leaf, SIG_tmp, root, pkSeed, adrs);
                }
            }

            for (int i = 0; i < SIG_HT.Length; ++i)
            {
                SIG_HT[i].CopyToSignature(signature, ref pos);
            }
        }

        private byte[] xmss_PKgen(byte[] skSeed, byte[] pkSeed, Adrs adrs)
        {
            return TreeHash(skSeed, 0, engine.H_PRIME, pkSeed, adrs);
        }

        // Input: index idx, XMSS signature SIG_XMSS = (sig || AUTH), n-byte message M, public seed PK.seed, address Adrs
        // Output: n-byte root value node[0]
        private byte[] xmss_pkFromSig(uint idx, SIG_XMSS sig_xmss, byte[] M, byte[] pkSeed, Adrs paramAdrs)
        {
            Adrs adrs = new Adrs(paramAdrs);

            // compute WOTS+ pk from WOTS+ sig
            adrs.SetAdrsType(Adrs.WOTS_HASH);
            adrs.SetKeyPairAddress(idx);
            byte[] sig = sig_xmss.WotsSig;
            byte[][] AUTH = sig_xmss.XmssAuth;

            byte[] node = new byte[engine.N];
            wots.PKFromSig(sig, M, pkSeed, adrs, node);

            // compute root from WOTS+ pk and AUTH
            adrs.SetAdrsType(Adrs.TREE);
            adrs.SetTreeIndex(idx);
            for (uint k = 0; k < engine.H_PRIME; k++)
            {
                adrs.SetTreeHeight(k + 1);
                if (((idx / (1 << (int)k)) % 2) == 0)
                {
                    adrs.SetTreeIndex(adrs.GetTreeIndex() / 2);
                    engine.H(pkSeed, adrs, node, AUTH[k], node);
                }
                else
                {
                    adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2);
                    engine.H(pkSeed, adrs, AUTH[k], node, node);
                }
            }

            return node;
        }

        //    # Input: n-byte message M, secret seed SK.seed, index idx, public seed PK.seed,
        //    address Adrs
        //    # Output: XMSS signature SIG_XMSS = (sig || AUTH)
        private SIG_XMSS xmss_sign(byte[] M, byte[] skSeed, uint idx, byte[] pkSeed, Adrs paramAdrs)
        {
            byte[][] AUTH = new byte[engine.H_PRIME][];
            
            Adrs adrs = new Adrs(paramAdrs);

            adrs.SetAdrsType(Adrs.TREE);
            adrs.SetLayerAddress(paramAdrs.GetLayerAddress());
            adrs.SetTreeAddress(paramAdrs.GetTreeAddress());


            // build authentication path
            for (int j = 0; j < engine.H_PRIME; j++)
            {
                uint k = (idx >> j) ^ 1;
                AUTH[j] = TreeHash(skSeed, k << j, (uint)j, pkSeed, adrs);
            }

            adrs = new Adrs(paramAdrs);
            adrs.SetAdrsType(Adrs.WOTS_HASH);
            adrs.SetKeyPairAddress(idx);

            byte[] sig = wots.Sign(M, skSeed, pkSeed, adrs);
            return new SIG_XMSS(sig, AUTH);
        }

        //
        // Input: Secret seed SK.seed, start index s, target node height z, public seed
        //PK.seed, address Adrs
        // Output: n-byte root node - top node on Stack
        private byte[] TreeHash(byte[] skSeed, uint s, uint z, byte[] pkSeed, Adrs adrsParam)
        {
            if (s % (1 << (int)z) != 0)
                return null;

            var stack = new Stack<NodeEntry>();
            Adrs adrs = new Adrs(adrsParam);

            for (uint idx = 0; idx < (1 << (int)z); idx++)
            {
                adrs.SetAdrsType(Adrs.WOTS_HASH);
                adrs.SetKeyPairAddress(s + idx);

                byte[] node = new byte[engine.N];
                wots.PKGen(skSeed, pkSeed, adrs, node);

                adrs.SetAdrsType(Adrs.TREE);
                adrs.SetTreeHeight(1);
                adrs.SetTreeIndex(s + idx);

                uint adrsTreeHeight = 1;
                uint adrsTreeIndex = s + idx;

                // while ( Top node on Stack has same height as node )
                while (stack.Count > 0 && stack.Peek().nodeHeight == adrsTreeHeight)
                {
                    adrsTreeIndex = (adrsTreeIndex - 1) / 2;
                    adrs.SetTreeIndex(adrsTreeIndex);

                    engine.H(pkSeed, adrs, stack.Pop().nodeValue, node, node);

                    //topmost node is now one layer higher
                    adrs.SetTreeHeight(++adrsTreeHeight);
                }

                stack.Push(new NodeEntry(node, adrsTreeHeight));
            }

            return stack.Peek().nodeValue;
        }

        //    # Input: Message M, signature SIG_HT, public seed PK.seed, tree index idx_tree,
        //    leaf index idx_leaf, HT public key PK_HT.
        //    # Output: bool
        internal bool Verify(byte[] M, SIG_XMSS[] sig_ht, byte[] pkSeed, ulong idx_tree, uint idx_leaf, byte[] PK_HT)
        {
            // init
            Adrs adrs = new Adrs();
            // verify
            SIG_XMSS SIG_tmp = sig_ht[0];
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);
            byte[] node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, pkSeed, adrs);
            for (uint j = 1; j < engine.D; j++)
            {
                idx_leaf = (uint) (idx_tree & (ulong)((1 << (int) engine.H_PRIME) - 1)); // least significant bits of idx_tree;
                idx_tree >>= (int) engine.H_PRIME; // most significant bits of idx_tree;
                SIG_tmp = sig_ht[j];
                adrs.SetLayerAddress(j);
                adrs.SetTreeAddress(idx_tree);
                node = xmss_pkFromSig(idx_leaf, SIG_tmp, node, pkSeed, adrs);
            }

            return Arrays.AreEqual(PK_HT, node);
        }
    }
}
