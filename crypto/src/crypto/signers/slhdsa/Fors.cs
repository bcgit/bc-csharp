using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

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
                    engine.H(adrs, current.NodeValue, 0, node, 0, node);

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
            byte[][] root = new byte[engine.K][];
            var indexGenerator = new IndexGenerator(engine.A);
            int forsPos = engine.N;

            // compute roots
            for (uint i = 0; i < engine.K; i++)
            {
                uint idx = indexGenerator.NextIndex(message);

                // compute leaf
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex((i << engine.A) + idx);

                // sig_fors[i].SK
                byte[] node = new byte[engine.N];
                Array.Copy(signature, forsPos, node, 0, engine.N);
                forsPos += engine.N;
                engine.F(adrs, node, 0);

                // compute root from leaf and AUTH
                uint adrsTreeIndex = (i << engine.A) + idx;

                for (int j = 0; j < engine.A; j++)
                {
                    // sig_fors[i].AuthPath[j]

                    adrs.SetTreeHeight((uint)j + 1);

                    if ((idx & (1U << j)) == 0U)
                    {
                        adrsTreeIndex = adrsTreeIndex / 2;
                        adrs.SetTreeIndex(adrsTreeIndex);
                        engine.H(adrs, node, 0, signature, forsPos, node);
                    }
                    else
                    {
                        adrsTreeIndex = (adrsTreeIndex - 1) / 2;
                        adrs.SetTreeIndex(adrsTreeIndex);
                        engine.H(adrs, signature, forsPos, node, 0, node);
                    }

                    forsPos += engine.N;
                }

                root[i] = node;
            }

            Adrs forspkAdrs = new Adrs(adrs, Adrs.ForsPK); // copy address to create FTS public key address
            forspkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());

            engine.T_l(forspkAdrs, Arrays.ConcatenateAll(root), output, outputOff);
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
