using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class HT
    {
        private readonly byte[] skSeed;
        private readonly byte[] pkSeed;

        internal readonly SlhDsaEngine engine;
        internal readonly WotsPlus wots;

        internal readonly byte[] HTPubKey;

        internal HT(SlhDsaEngine engine, byte[] skSeed, byte[] pkSeed)
        {
            this.skSeed = skSeed;
            this.pkSeed = pkSeed;

            this.engine = engine;
            this.wots = new WotsPlus(engine);

            Adrs adrs = new Adrs();
            adrs.SetLayerAddress((uint)engine.D - 1U);
            adrs.SetTreeAddress(0);

            byte[] htPubKey = null;
            if (skSeed != null)
            {
                htPubKey = new byte[engine.N];
                TreeHash(skSeed, 0, engine.HPrime, pkSeed, adrs, htPubKey, 0);
            }
            this.HTPubKey = htPubKey;
        }

        internal void Sign(byte[] M, ulong idx_tree, uint idx_leaf, byte[] signature)
        {
            // init
            Adrs adrs = new Adrs();
            // sign
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);

            int sigXmssPos = GetXmssOffset(engine);

            int pos0 = sigXmssPos;
            xmss_sign(M, skSeed, idx_leaf, pkSeed, adrs, signature, ref sigXmssPos);

            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);

            byte[] root = xmss_pkFromSig(idx_leaf, signature, pos0, M, pkSeed, adrs);

            for (uint j = 1; j < engine.D; j++)
            {
                // least significant bits of idx_tree;
                // TODO[slh-dsa] Might not be working as intended
                idx_leaf = (uint)(idx_tree & (ulong)((1 << engine.HPrime) - 1));
                // most significant bits of idx_tree;
                idx_tree >>= engine.HPrime;
                adrs.SetLayerAddress(j);
                adrs.SetTreeAddress(idx_tree);

                int posj = sigXmssPos;
                xmss_sign(root, skSeed, idx_leaf, pkSeed, adrs, signature, ref sigXmssPos);

                if (j < engine.D - 1)
                {
                    root = xmss_pkFromSig(idx_leaf, signature, posj, root, pkSeed, adrs);
                }
            }
        }

        private byte[] xmss_pkFromSig(uint idx, byte[] sigXmss, int sigXmssOff, byte[] M, byte[] pkSeed, Adrs paramAdrs)
        {
            int n = engine.N;

            // compute WOTS+ pk from WOTS+ sig
            Adrs adrs = new Adrs(paramAdrs, Adrs.WotsHash);
            adrs.SetKeyPairAddress(idx);

            // WotsSig
            byte[] node = new byte[engine.N];
            wots.PKFromSig(sigXmss, sigXmssOff, M, pkSeed, adrs, node, 0);
            sigXmssOff += engine.WotsLen * n;

            // compute root from WOTS+ pk and AUTH
            adrs.SetTypeAndClear(Adrs.Tree);
            adrs.SetTreeIndex(idx);

            for (int k = 0; k < engine.HPrime; ++k)
            {
                // XmssAuth[k]
                adrs.SetTreeHeight((uint)(k + 1));
                if ((idx & (1U << k)) == 0U)
                {
                    adrs.SetTreeIndex(adrs.GetTreeIndex() / 2);
                    engine.H1(adrs, node, 0, sigXmss, sigXmssOff);
                }
                else
                {
                    adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2);
                    engine.H2(adrs, sigXmss, sigXmssOff, node, 0);
                }
                sigXmssOff += engine.N;
            }

            return node;
        }

        private void xmss_sign(byte[] M, byte[] skSeed, uint idx, byte[] pkSeed, Adrs paramAdrs, byte[] sigXmss,
            ref int sigXmssPos)
        {
            Adrs adrs = new Adrs(paramAdrs, Adrs.WotsHash);
            adrs.SetKeyPairAddress(idx);

            wots.Sign(M, skSeed, pkSeed, adrs, sigXmss, sigXmssPos);
            sigXmssPos += engine.WotsLen * engine.N;

            adrs = new Adrs(paramAdrs, Adrs.Tree);

            // build authentication path
            for (int j = 0; j < engine.HPrime; j++)
            {
                uint k = (idx >> j) ^ 1;
                TreeHash(skSeed, k << j, j, pkSeed, adrs, sigXmss, sigXmssPos);
                sigXmssPos += engine.N;
            }
        }

        private void TreeHash(byte[] skSeed, uint s, int z, byte[] pkSeed, Adrs adrsParam, byte[] output, int outputOff)
        {
            if ((s >> z) << z != s)
                throw new InvalidOperationException();

            int n = engine.N;
            var stack = new Stack<NodeEntry>();
            Adrs adrs = new Adrs(adrsParam);

            for (uint idx = 0; idx < (1U << z); idx++)
            {
                adrs.SetTypeAndClear(Adrs.WotsHash);
                adrs.SetKeyPairAddress(s + idx);

                byte[] node = new byte[n];
                wots.PKGen(skSeed, pkSeed, adrs, node, 0);

                adrs.SetTypeAndClear(Adrs.Tree);
                adrs.SetTreeHeight(1);
                adrs.SetTreeIndex(s + idx);

                uint adrsTreeHeight = 1;
                uint adrsTreeIndex = s + idx;

                // while ( Top node on Stack has same height as node )
                while (stack.Count > 0 && stack.Peek().NodeHeight == adrsTreeHeight)
                {
                    adrsTreeIndex = (adrsTreeIndex - 1) / 2;
                    adrs.SetTreeIndex(adrsTreeIndex);

                    var current = stack.Pop();
                    engine.H2(adrs, current.NodeValue, 0, node, 0);

                    // topmost node is now one layer higher
                    adrs.SetTreeHeight(++adrsTreeHeight);
                }

                stack.Push(new NodeEntry(node, adrsTreeHeight));
            }

            Array.Copy(stack.Peek().NodeValue, 0, output, outputOff, n);
        }

        internal bool Verify(byte[] M, byte[] signature, byte[] pkSeed, ulong idx_tree, uint idx_leaf, byte[] PK_HT)
        {
            int xmssPos = GetXmssOffset(engine);

            // init
            Adrs adrs = new Adrs();
            adrs.SetLayerAddress(0);
            adrs.SetTreeAddress(idx_tree);

            // verify
            byte[] node = xmss_pkFromSig(idx_leaf, signature, xmssPos, M, pkSeed, adrs);

            for (uint j = 1; j < engine.D; j++)
            {
                idx_leaf = (uint)(idx_tree & (ulong)((1 << engine.HPrime) - 1)); // least significant bits of idx_tree;
                idx_tree >>= engine.HPrime; // most significant bits of idx_tree;

                adrs.SetLayerAddress(j);
                adrs.SetTreeAddress(idx_tree);

                xmssPos += (engine.HPrime + engine.WotsLen) * engine.N;
                node = xmss_pkFromSig(idx_leaf, signature, xmssPos, node, pkSeed, adrs);
            }

            return Arrays.AreEqual(PK_HT, node);
        }

        private static int GetXmssOffset(SlhDsaEngine engine) => (((engine.A + 1) * engine.K) + 1) * engine.N;
    }
}
