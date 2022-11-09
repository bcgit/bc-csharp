using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class Fors
    {
        private readonly SphincsPlusEngine engine;

        internal Fors(SphincsPlusEngine engine)
        {
            this.engine = engine;
        }

        // Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address Adrs
        // Output: n-byte root node - top node on Stack
        internal byte[] TreeHash(byte[] skSeed, uint s, int z, byte[] pkSeed, Adrs adrsParam)
        {
            if (s % (1 << z) != 0)
                return null;

            var stack = new Stack<NodeEntry>();
            Adrs adrs = new Adrs(adrsParam);
            byte[] sk = new byte[engine.N];

            for (uint idx = 0; idx < (1 << z); idx++)
            {
                adrs.SetAdrsType(Adrs.FORS_PRF);
                adrs.SetKeyPairAddress(adrsParam.GetKeyPairAddress());
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex(s + idx);

                engine.PRF(pkSeed, skSeed, adrs, sk, 0);
                
                adrs.ChangeAdrsType(Adrs.FORS_TREE);

                byte[] node = engine.F(pkSeed, adrs, sk);

                adrs.SetTreeHeight(1);

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

        internal SIG_FORS[] Sign(byte[] md, byte[] skSeed, byte[] pkSeed, Adrs paramAdrs)
        {
            Adrs adrs = new Adrs(paramAdrs);
            SIG_FORS[] sig_fors = new SIG_FORS[engine.K];
            // compute signature elements
            uint t = engine.T;
            for (uint i = 0; i < engine.K; i++)
            {
                // get next index
                uint idx = GetMessageIdx(md, (int)i, engine.A);

                // pick private key element
                adrs.SetAdrsType(Adrs.FORS_PRF);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex((uint) (i * t + idx));

                byte[] sk = new byte[engine.N];
                engine.PRF(pkSeed, skSeed, adrs, sk, 0);

                adrs.ChangeAdrsType(Adrs.FORS_TREE);

                byte[][] authPath = new byte[engine.A][];
                // compute auth path
                for (int j = 0; j < engine.A; j++)
                {
                    uint s = (idx >> j) ^ 1U;
                    authPath[j] = TreeHash(skSeed, (uint) (i * t + (s << j)), j, pkSeed, adrs);
                }

                sig_fors[i] = new SIG_FORS(sk, authPath);
            }

            return sig_fors;
        }

        internal byte[] PKFromSig(SIG_FORS[] sig_fors, byte[] message, byte[] pkSeed, Adrs adrs)
        {
            byte[][] root = new byte[engine.K][];
            uint t = engine.T;

            // compute roots
            for (uint i = 0; i < engine.K; i++)
            {
                // get next index
                uint idx = GetMessageIdx(message, (int)i, engine.A);

                // compute leaf
                byte[] sk = sig_fors[i].SK;
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex(i * t + idx);
                byte[] node = engine.F(pkSeed, adrs, sk);

                // compute root from leaf and AUTH
                byte[][] authPath = sig_fors[i].AuthPath;
                uint adrsTreeIndex = i * t + idx;
                for (int j = 0; j < engine.A; j++)
                {
                    adrs.SetTreeHeight((uint)j + 1);
                    if (((idx >> j) % 2) == 0U)
                    {
                        adrsTreeIndex = adrsTreeIndex / 2;
                        adrs.SetTreeIndex(adrsTreeIndex);
                        engine.H(pkSeed, adrs, node, authPath[j], node);
                    }
                    else
                    {
                        adrsTreeIndex = (adrsTreeIndex - 1) / 2;
                        adrs.SetTreeIndex(adrsTreeIndex);
                        engine.H(pkSeed, adrs, authPath[j], node, node);
                    }
                }

                root[i] = node;
            }

            Adrs forspkAdrs = new Adrs(adrs); // copy address to create FTS public key address
            forspkAdrs.SetAdrsType(Adrs.FORS_PK);
            forspkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());

            byte[] result = new byte[engine.N];
            engine.T_l(pkSeed, forspkAdrs, Arrays.ConcatenateAll(root), result);
            return result;
        }

        /**
         * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
         * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
         * Assumes indices has space for SPX_FORS_TREES integers.
         */
        private static uint GetMessageIdx(byte[] msg, int fors_tree, int fors_height)
        {
            int offset = fors_tree * fors_height;
            uint idx = 0;
            for (int bit = 0; bit < fors_height; bit++)
            {
                idx ^= (((uint)msg[offset >> 3] >> (offset & 0x7)) & 1U) << bit;
                offset++;
            }
            return idx;
        }
    }
}
