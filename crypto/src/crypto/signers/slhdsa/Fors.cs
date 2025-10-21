using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal static class Fors
    {
        internal static void TreeHash(SlhDsaEngine engine, byte[] skSeed, uint s, int z, Adrs adrsParam, byte[] output,
            int outputOff)
        {
            if ((s >> z) << z != s)
                throw new InvalidOperationException();

            var stack = new Stack<NodeEntry>();
            var adrs = new Adrs(adrsParam);

            for (uint idx = 0; idx < (1U << z); idx++)
            {
                adrs.SetTypeAndClear(Adrs.ForsPrf);
                adrs.SetKeyPairAddress(adrsParam.GetKeyPairAddress());
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex(s + idx);

                byte[] node = new byte[engine.N];
                engine.Prf(adrs, skSeed, node, 0);

                adrs.SetType(Adrs.ForsTree);

                engine.F(adrs, node, 0);

                adrs.SetTreeHeight(1);

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

            Array.Copy(stack.Peek().NodeValue, 0, output, outputOff, engine.N);
        }

        internal static void Sign(SlhDsaEngine engine, byte[] md, byte[] skSeed, Adrs paramAdrs, byte[] signature)
        {
            Adrs adrs = new Adrs(paramAdrs);
            var indexGenerator = new IndexGenerator(engine.A);
            int forsPos = engine.N;

            // compute signature elements
            for (uint i = 0; i < engine.K; i++)
            {
                uint index = indexGenerator.NextIndex(md);

                // pick private key element
                adrs.SetTypeAndClear(Adrs.ForsPrf);
                adrs.SetKeyPairAddress(paramAdrs.GetKeyPairAddress());
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex((i << engine.A) + index);

                // sig_fors[i].SK
                engine.Prf(adrs, skSeed, signature, forsPos);
                forsPos += engine.N;

                adrs.SetType(Adrs.ForsTree);

                // compute auth path
                for (int j = 0; j < engine.A; j++)
                {
                    // sig_fors[i].AuthPath[j]
                    uint s = (index >> j) ^ 1U;
                    TreeHash(engine, skSeed, (i << engine.A) + (s << j), j, adrs, signature, forsPos);
                    forsPos += engine.N;
                }
            }
        }

        internal static void PKFromSig(SlhDsaEngine engine, byte[] signature, byte[] message, Adrs adrs, byte[] output,
            int outputOff)
        {
            int a = engine.A, k = engine.K, n = engine.N;

            byte[] roots = new byte[k * n];
            var indexGenerator = new IndexGenerator(a);
            int forsPos = n;

            // compute roots
            for (int i = 0, rootsPos = 0; i < k; ++i, rootsPos += n)
            {
                uint idx = indexGenerator.NextIndex(message);

                // compute root from leaf and AUTH
                uint adrsTreeIndex = ((uint)i << a) + idx;

                // compute leaf
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex(adrsTreeIndex);

                // sig_fors[i].SK
                Array.Copy(signature, forsPos, roots, rootsPos, n);
                forsPos += n;
                engine.F(adrs, roots, rootsPos);

                for (int j = 0; j < a; j++)
                {
                    // sig_fors[i].AuthPath[j]

                    adrs.SetTreeHeight((uint)j + 1);

                    if ((idx & (1U << j)) == 0U)
                    {
                        adrsTreeIndex = adrsTreeIndex / 2;
                        adrs.SetTreeIndex(adrsTreeIndex);
                        engine.H1(adrs, roots, rootsPos, signature, forsPos);
                    }
                    else
                    {
                        adrsTreeIndex = (adrsTreeIndex - 1) / 2;
                        adrs.SetTreeIndex(adrsTreeIndex);
                        engine.H2(adrs, signature, forsPos, roots, rootsPos);
                    }

                    forsPos += n;
                }
            }

            // copy address to create FTS public key address
            Adrs forspkAdrs = new Adrs(adrs, Adrs.ForsPK);
            forspkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());

            engine.T_l(forspkAdrs, roots, output, outputOff);
        }

        private struct IndexGenerator
        {
            private readonly int m_bitsPerIndex;
            private readonly uint m_indexMask;

            private int m_availableBits, m_messagePos;
            private uint m_indexValue;

            internal IndexGenerator(int bitsPerIndex)
            {
                m_bitsPerIndex = bitsPerIndex;
                m_indexMask = (1U << bitsPerIndex) - 1U;

                m_availableBits = 0;
                m_messagePos = 0;
                m_indexValue = 0U;
            }

            internal uint NextIndex(byte[] message)
            {
                while (m_availableBits < m_bitsPerIndex)
                {
                    m_availableBits += 8;
                    m_indexValue <<= 8;
                    m_indexValue |= message[m_messagePos++];
                }

                m_availableBits -= m_bitsPerIndex;
                return (m_indexValue >> m_availableBits) & m_indexMask;
            }
        }
    }
}
