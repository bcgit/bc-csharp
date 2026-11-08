using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>
    /// Codec for the implementation-specific BDS traversal state stored with an XMSS or XMSS^MT private key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 8391 Sections 4.1.7 and 4.2.2 leave the private-key representation unspecified, and Section 4.1.9 refers
    /// to BDS [BDS09] only as one of the authentication-path computation optimizations. Consequently, this
    /// versioned encoding is a BC private-key implementation detail, not an RFC-defined interchange format. It is
    /// the one bc-java writes, byte for byte, so a private key encoded by either reads in the other.
    /// </para>
    /// <para>
    /// All integers are big-endian, as Java's <c>DataOutputStream</c> writes them. Every failure to decode is an
    /// <see cref="IOException"/>, running out of data included (<see cref="EndOfStreamException"/>).
    /// </para>
    /// <para>
    /// The single-tree state is <see cref="Encode(Bds, byte[])"/> and <see cref="DecodeBds"/>. The XMSS^MT state map
    /// is written by <see cref="Encode(BdsStateMap, byte[])"/> as <see cref="BdsStateMapMagic"/>, version, the
    /// maximum index, a count and then one layer number and <see cref="WriteBds"/> body per layer, in ascending
    /// layer order, and read back by <see cref="DecodeBdsStateMap"/> with <see cref="ReadBds"/> under one
    /// <see cref="NodeBudget"/> for the whole map.
    /// </para>
    /// </remarks>
    internal static class BdsStateCodec
    {
        internal const int BdsStateMagic = 0x42445300;
        internal const int BdsStateMapMagic = 0x42444d00;

        private const int StateVersion = 1;
        private const int MaxEncodedStateSize = 4 * 1024 * 1024;
        private const int MaxDigestSize = 64;
        internal const int MaxStateMapEntries = 64;
        private const int MaxNodes = 4096;
        private const int ChecksumSize = 32;

        internal static bool IsBdsStateEncoding(byte[] encoding) => HasMagic(encoding, BdsStateMagic);

        internal static bool IsBdsStateMapEncoding(byte[] encoding) => HasMagic(encoding, BdsStateMapMagic);

        internal static byte[] Encode(Bds state, byte[] publicSeed)
        {
            Writer dataOut = new Writer();
            dataOut.WriteInt(BdsStateMagic);
            dataOut.WriteInt(StateVersion);
            WriteBds(dataOut, state);
            return CheckedEncoding(WithChecksum(dataOut, publicSeed));
        }

        internal static Bds DecodeBds(byte[] encoding, byte[] publicSeed)
        {
            CheckEncodingSize(encoding);
            Reader dataIn = new Reader(encoding, CheckedBodyLength(encoding, publicSeed));
            ReadHeader(dataIn, BdsStateMagic);
            Bds state = ReadBds(dataIn, new NodeBudget());
            CheckFinished(dataIn);
            return state;
        }

        internal static byte[] Encode(BdsStateMap stateMap, byte[] publicSeed)
        {
            Writer dataOut = new Writer();
            dataOut.WriteInt(BdsStateMapMagic);
            dataOut.WriteInt(StateVersion);
            dataOut.WriteLong(stateMap.MaxIndex);

            // a snapshot: the map can be one a key is signing with
            SortedDictionary<int, Bds> states = stateMap.GetStateMap();
            if (states.Count > MaxStateMapEntries)
                throw new IOException("too many BDS states");

            dataOut.WriteInt(states.Count);
            foreach (var entry in states)
            {
                dataOut.WriteInt(entry.Key);
                WriteBds(dataOut, entry.Value);
            }
            return CheckedEncoding(WithChecksum(dataOut, publicSeed));
        }

        /// <remarks>
        /// The layers come back in strictly ascending order or not at all; each layer's state is read as
        /// <see cref="DecodeBds"/> reads one, under one node budget for the whole map. The map comes back without
        /// WOTS+ instances in its layers; the caller gives it them with
        /// <see cref="BdsStateMap.WithMaxIndex(long, Org.BouncyCastle.Asn1.DerObjectIdentifier, int)"/> before it is
        /// used.
        /// </remarks>
        internal static BdsStateMap DecodeBdsStateMap(byte[] encoding, byte[] publicSeed)
        {
            CheckEncodingSize(encoding);
            Reader dataIn = new Reader(encoding, CheckedBodyLength(encoding, publicSeed));
            ReadHeader(dataIn, BdsStateMapMagic);

            long maxIndex = dataIn.ReadLong();
            if (maxIndex < 0)
                throw new IOException("negative BDS state map maxIndex");

            int stateCount = ReadCount(dataIn, MaxStateMapEntries, "BDS state map");
            BdsStateMap stateMap = new BdsStateMap(maxIndex);
            NodeBudget nodeBudget = new NodeBudget();
            int previousLayer = -1;
            for (int i = 0; i < stateCount; i++)
            {
                int layer = dataIn.ReadInt();
                if (layer <= previousLayer)
                    throw new IOException("invalid BDS state map layer");

                stateMap.Put(layer, ReadBds(dataIn, nodeBudget));
                previousLayer = layer;
            }
            CheckFinished(dataIn);
            return stateMap;
        }

        private static void WriteBds(Writer dataOut, Bds state)
        {
            try
            {
                state.Validate();
            }
            catch (InvalidOperationException e)
            {
                throw InvalidState(e);
            }

            int treeHeight = state.TreeHeight;
            dataOut.WriteInt(treeHeight);
            dataOut.WriteInt(state.K);
            dataOut.WriteInt(state.MaxIndex);
            dataOut.WriteInt(state.Index);
            WriteBoolean(dataOut, state.IsUsed);
            WriteOptionalNode(dataOut, state.Root, treeHeight);

            List<XmssNode> authenticationPath = state.LiveAuthenticationPath;
            dataOut.WriteInt(authenticationPath.Count);
            for (int i = 0; i < authenticationPath.Count; i++)
            {
                WriteNode(dataOut, authenticationPath[i], treeHeight);
            }

            SortedDictionary<int, List<XmssNode>> retain = state.LiveRetain;
            dataOut.WriteInt(retain.Count);
            foreach (var entry in retain)
            {
                List<XmssNode> nodes = entry.Value;
                if (nodes == null)
                    throw new IOException("null BDS retain queue");

                dataOut.WriteInt(entry.Key);
                dataOut.WriteInt(nodes.Count);
                WriteNodes(dataOut, nodes, treeHeight);
            }

            // bottom to top, as Java's Stack iterates
            List<XmssNode> stack = state.LiveStack;
            dataOut.WriteInt(stack.Count);
            WriteNodes(dataOut, stack, treeHeight);

            List<BdsTreeHash> treeHashes = state.LiveTreeHashInstances;
            dataOut.WriteInt(treeHashes.Count);
            foreach (BdsTreeHash treeHash in treeHashes)
            {
                if (treeHash == null)
                    throw new IOException("null BDS tree hash");

                dataOut.WriteInt(treeHash.InitialHeight);
                dataOut.WriteInt(treeHash.RawHeight);
                dataOut.WriteInt(treeHash.IndexLeaf);
                WriteBoolean(dataOut, treeHash.IsInitialized);
                WriteBoolean(dataOut, treeHash.IsFinished);
                WriteOptionalNode(dataOut, treeHash.TailNode, treeHeight);
            }

            SortedDictionary<int, XmssNode> keep = state.LiveKeep;
            dataOut.WriteInt(keep.Count);
            foreach (var entry in keep)
            {
                dataOut.WriteInt(entry.Key);
                WriteNode(dataOut, entry.Value, treeHeight);
            }
        }

        private static Bds ReadBds(Reader dataIn, NodeBudget nodeBudget)
        {
            int treeHeight = dataIn.ReadInt();
            int k = dataIn.ReadInt();
            int maxIndex = dataIn.ReadInt();
            int index = dataIn.ReadInt();
            bool used = ReadBoolean(dataIn);

            if (treeHeight < 2 || treeHeight > XmssParameters.MaxHeight)
                throw new IOException("BDS tree height out of bounds");
            // k controls the BDS time-memory trade-off; it is not an XMSS wire parameter. The BDS traversal layout
            // requires 2 <= k <= treeHeight and an even treeHeight - k.
            if (k < 2 || k > treeHeight || ((treeHeight - k) & 1) != 0)
                throw new IOException("BDS k out of bounds");

            int maxIndexLimit = (1 << treeHeight) - 1;
            if (maxIndex < 0 || maxIndex > maxIndexLimit || index < 0 || index > maxIndex + 1)
                throw new IOException("BDS index out of bounds");

            XmssNode root = ReadOptionalNode(dataIn, treeHeight, nodeBudget);
            if (root != null && root.Height != treeHeight)
                throw new IOException("BDS root has wrong height");

            int authenticationPathCount = ReadCount(dataIn, treeHeight, "BDS authentication path");
            if (authenticationPathCount != 0 && authenticationPathCount != treeHeight)
                throw new IOException("BDS authentication path has wrong size");

            List<XmssNode> authenticationPath = new List<XmssNode>(authenticationPathCount);
            for (int i = 0; i < authenticationPathCount; i++)
            {
                authenticationPath.Add(ReadNode(dataIn, i, i, nodeBudget));
            }
            if ((root == null) != (authenticationPath.Count == 0))
                throw new IOException("inconsistent BDS root and authentication path");

            int retainCount = ReadCount(dataIn, k - 1, "BDS retain map");
            var retain = new SortedDictionary<int, List<XmssNode>>();
            int previousRetainHeight = treeHeight - k - 1;
            for (int i = 0; i < retainCount; i++)
            {
                int height = dataIn.ReadInt();
                if (height <= previousRetainHeight || height > treeHeight - 2)
                    throw new IOException("invalid BDS retain height");

                int maximumRetained = (1 << (treeHeight - height - 1)) - 1;
                int nodeCount = ReadCount(dataIn, System.Math.Min(maximumRetained, nodeBudget.Remaining),
                    "BDS retain queue");
                List<XmssNode> nodes = new List<XmssNode>(nodeCount);
                for (int j = 0; j < nodeCount; j++)
                {
                    nodes.Add(ReadNode(dataIn, height, height, nodeBudget));
                }
                retain.Add(height, nodes);
                previousRetainHeight = height;
            }

            int stackCount = ReadCount(dataIn, System.Math.Min(treeHeight, nodeBudget.Remaining), "BDS stack");
            List<XmssNode> stack = new List<XmssNode>(stackCount);
            for (int i = 0; i < stackCount; i++)
            {
                stack.Add(ReadNode(dataIn, 0, treeHeight, nodeBudget));
            }

            int expectedTreeHashCount = treeHeight - k;
            int treeHashCount = ReadCount(dataIn, expectedTreeHashCount, "BDS tree hash");
            if (treeHashCount != expectedTreeHashCount)
                throw new IOException("BDS tree hash has wrong size");

            List<BdsTreeHash> treeHashes = new List<BdsTreeHash>(treeHashCount);
            for (int i = 0; i < treeHashCount; i++)
            {
                int initialHeight = dataIn.ReadInt();
                int height = dataIn.ReadInt();
                int nextIndex = dataIn.ReadInt();
                bool initialized = ReadBoolean(dataIn);
                bool finished = ReadBoolean(dataIn);
                if (initialHeight != i || height < 0 || height > initialHeight
                    || nextIndex < 0 || nextIndex > maxIndexLimit)
                {
                    throw new IOException("invalid BDS tree hash state");
                }
                XmssNode tailNode = ReadOptionalNode(dataIn, treeHeight, nodeBudget);
                if (tailNode != null && tailNode.Height > initialHeight)
                    throw new IOException("BDS tree hash tail has wrong height");

                treeHashes.Add(new BdsTreeHash(initialHeight, height, nextIndex, initialized, finished, tailNode));
            }

            int keepCount = ReadCount(dataIn, System.Math.Min(treeHeight, nodeBudget.Remaining), "BDS keep map");
            var keep = new SortedDictionary<int, XmssNode>();
            int previousKeepHeight = -1;
            for (int i = 0; i < keepCount; i++)
            {
                int height = dataIn.ReadInt();
                if (height <= previousKeepHeight || height > treeHeight - 2)
                    throw new IOException("invalid BDS keep height");

                keep.Add(height, ReadNode(dataIn, height, height, nodeBudget));
                previousKeepHeight = height;
            }

            try
            {
                return new Bds(treeHeight, k, maxIndex, index, used, root, authenticationPath, retain, stack,
                    treeHashes, keep);
            }
            catch (InvalidOperationException e)
            {
                throw InvalidState(e);
            }
        }

        private static void WriteNodes(Writer dataOut, IEnumerable<XmssNode> nodes, int treeHeight)
        {
            foreach (XmssNode node in nodes)
            {
                WriteNode(dataOut, node, treeHeight);
            }
        }

        private static void WriteOptionalNode(Writer dataOut, XmssNode node, int treeHeight)
        {
            WriteBoolean(dataOut, node != null);
            if (node != null)
            {
                WriteNode(dataOut, node, treeHeight);
            }
        }

        private static void WriteNode(Writer dataOut, XmssNode node, int treeHeight)
        {
            if (node == null)
                throw new IOException("null XMSS node");
            int valueLength = node.ValueLength;
            if (node.Height < 0 || node.Height > treeHeight || valueLength < 1 || valueLength > MaxDigestSize)
                throw new IOException("XMSS node out of bounds");

            dataOut.WriteInt(node.Height);
            dataOut.WriteInt(valueLength);
            dataOut.WriteNode(node);
        }

        private static XmssNode ReadOptionalNode(Reader dataIn, int treeHeight, NodeBudget nodeBudget)
        {
            if (!ReadBoolean(dataIn))
                return null;

            return ReadNode(dataIn, 0, treeHeight, nodeBudget);
        }

        private static XmssNode ReadNode(Reader dataIn, int minimumHeight, int maximumHeight, NodeBudget nodeBudget)
        {
            nodeBudget.Consume();
            int height = dataIn.ReadInt();
            int valueSize = dataIn.ReadInt();
            if (height < minimumHeight || height > maximumHeight)
                throw new IOException("XMSS node height out of bounds");
            if (valueSize < 1 || valueSize > MaxDigestSize)
                throw new IOException("XMSS node value size out of bounds");

            nodeBudget.SetDigestSize(valueSize);
            byte[] value = new byte[valueSize];
            dataIn.ReadFully(value);
            return new XmssNode(height, value);
        }

        /// <summary>
        /// The trailing checksum over the encoded state, with the key's public seed hashed in front of it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>This is an error-detecting code, not integrity protection.</b> Anyone able to rewrite the stored
        /// private key can recompute it, so it authenticates nothing; what it catches is accidental corruption -
        /// bit rot, a partial write, a truncated record - of the node values inside the state, which cannot be
        /// checked any other way. A BDS authentication path, stack, retain or keep node does not have its children
        /// stored beside it, so recomputing one means rebuilding a subtree, which is the work this state exists to
        /// avoid.
        /// </para>
        /// <para>
        /// The public seed is hashed in to tie the state to the key it belongs to, so a state transplanted between
        /// two keys of the same parameters fails here even though it is internally consistent. The seed is a public
        /// value, deliberately - hashing the secret seed or the PRF key instead would make the stored checksum a
        /// commitment to secret material for no gain in detection.
        /// </para>
        /// <para>
        /// The digest is SHA-256 whatever the parameter set's tree digest is: this is a checksum over an
        /// implementation-detail encoding, not part of any scheme.
        /// </para>
        /// </remarks>
        /// <param name="encoding">the buffer holding the body.</param>
        /// <param name="length">the length of the body at the start of it.</param>
        /// <param name="publicSeed">the key's public seed, or null to bind nothing.</param>
        /// <param name="output">where the checksum goes.</param>
        /// <param name="outOff">the offset in it.</param>
        private static void ChecksumTo(byte[] encoding, int length, byte[] publicSeed, byte[] output, int outOff)
        {
            IDigest digest = new Sha256Digest();

            if (publicSeed != null)
            {
                digest.BlockUpdate(publicSeed, 0, publicSeed.Length);
            }
            digest.BlockUpdate(encoding, 0, length);

            digest.DoFinal(output, outOff);
        }

        /// <summary>The encoding held by <paramref name="dataOut"/>, with its checksum appended.</summary>
        private static byte[] WithChecksum(Writer dataOut, byte[] publicSeed)
        {
            int bodyLength = dataOut.Length;
            dataOut.WriteZeros(ChecksumSize);

            byte[] encoding = dataOut.ToArray();
            ChecksumTo(encoding, bodyLength, publicSeed, encoding, bodyLength);

            return encoding;
        }

        /// <summary>
        /// Verify the trailing checksum and return the length of the body it covers, so the caller can read the
        /// body in place rather than copying it out.
        /// </summary>
        private static int CheckedBodyLength(byte[] encoding, byte[] publicSeed)
        {
            if (encoding.Length < ChecksumSize + 8)
                throw new IOException("BDS state encoding size out of bounds");

            int bodyLength = encoding.Length - ChecksumSize;
            byte[] expected = new byte[ChecksumSize];
            ChecksumTo(encoding, bodyLength, publicSeed, expected, 0);

            // an error-detecting checksum over material that is not secret, so a plain comparison is what is
            // wanted here - see the note on ChecksumTo
            if (!Arrays.AreEqual(expected, 0, ChecksumSize, encoding, bodyLength, encoding.Length))
                throw new IOException("BDS state checksum does not match");

            return bodyLength;
        }

        private static void ReadHeader(Reader dataIn, int expectedMagic)
        {
            if (dataIn.ReadInt() != expectedMagic)
                throw new IOException("unexpected BDS state magic");
            if (dataIn.ReadInt() != StateVersion)
                throw new IOException("unsupported BDS state version");
        }

        private static bool ReadBoolean(Reader dataIn)
        {
            int value = dataIn.ReadUnsignedByte();
            if (value > 1)
                throw new IOException("invalid boolean in BDS state");

            return value == 1;
        }

        private static void WriteBoolean(Writer dataOut, bool value) => dataOut.WriteByte(value ? 1 : 0);

        private static int ReadCount(Reader dataIn, int maximum, string name)
        {
            int count = dataIn.ReadInt();
            if (count < 0 || count > maximum)
                throw new IOException(name + " size out of bounds");

            return count;
        }

        private static void CheckFinished(Reader dataIn)
        {
            if (dataIn.Available != 0)
                throw new IOException("unexpected data at end of BDS state");
        }

        private static byte[] CheckedEncoding(byte[] encoding)
        {
            CheckEncodingSize(encoding);
            return encoding;
        }

        internal static void CheckEncodingSize(byte[] encoding)
        {
            if (encoding == null || encoding.Length < 8 || encoding.Length > MaxEncodedStateSize)
                throw new IOException("BDS state encoding size out of bounds");
        }

        private static bool HasMagic(byte[] encoding, int magic) =>
            encoding != null && encoding.Length >= 4 && (int)Pack.BE_To_UInt32(encoding, 0) == magic;

        private static IOException InvalidState(InvalidOperationException cause) =>
            new IOException("invalid BDS state", cause);

        /// <summary>
        /// The total number of nodes one encoding may hold, and the one node value size all of them must share.
        /// </summary>
        private sealed class NodeBudget
        {
            private int m_remaining = MaxNodes;
            private int m_digestSize;

            internal int Remaining => m_remaining;

            internal void Consume()
            {
                if (m_remaining == 0)
                    throw new IOException("too many XMSS nodes in BDS state");

                m_remaining--;
            }

            internal void SetDigestSize(int valueSize)
            {
                if (m_digestSize == 0)
                {
                    m_digestSize = valueSize;
                }
                else if (m_digestSize != valueSize)
                {
                    throw new IOException("inconsistent XMSS node value sizes");
                }
            }
        }

        /// <summary>The write side of Java's <c>DataOutputStream</c> this encoding uses: big-endian.</summary>
        private sealed class Writer
        {
            private readonly MemoryStream m_buffer = new MemoryStream();
            private readonly byte[] m_word = new byte[4];

            internal int Length => (int)m_buffer.Length;

            internal void WriteInt(int value)
            {
                Pack.UInt32_To_BE((uint)value, m_word, 0);
                m_buffer.Write(m_word, 0, 4);
            }

            internal void WriteLong(long value)
            {
                Pack.UInt32_To_BE((uint)(value >> 32), m_word, 0);
                m_buffer.Write(m_word, 0, 4);
                Pack.UInt32_To_BE((uint)value, m_word, 0);
                m_buffer.Write(m_word, 0, 4);
            }

            internal void WriteByte(int value) => m_buffer.WriteByte((byte)value);

            internal void WriteNode(XmssNode node) => node.EncodeTo(m_buffer);

            internal void WriteZeros(int count) => m_buffer.Write(new byte[count], 0, count);

            internal byte[] ToArray() => m_buffer.ToArray();
        }

        /// <summary>
        /// The read side of Java's <c>DataInputStream</c> this encoding uses, over the body of an encoding in
        /// place. Reading past the body is an <see cref="EndOfStreamException"/>, as Java's is an
        /// <c>EOFException</c>.
        /// </summary>
        private sealed class Reader
        {
            private readonly byte[] m_buffer;
            private readonly int m_limit;
            private int m_position;

            internal Reader(byte[] buffer, int limit)
            {
                m_buffer = buffer;
                m_limit = limit;
                m_position = 0;
            }

            internal int Available => m_limit - m_position;

            internal int ReadInt()
            {
                Require(4);
                int value = (int)Pack.BE_To_UInt32(m_buffer, m_position);
                m_position += 4;
                return value;
            }

            internal long ReadLong()
            {
                Require(8);
                long value = (long)Pack.BE_To_UInt64(m_buffer, m_position);
                m_position += 8;
                return value;
            }

            internal int ReadUnsignedByte()
            {
                Require(1);
                return m_buffer[m_position++];
            }

            internal void ReadFully(byte[] output)
            {
                Require(output.Length);
                Array.Copy(m_buffer, m_position, output, 0, output.Length);
                m_position += output.Length;
            }

            private void Require(int count)
            {
                if (count > Available)
                    throw new EndOfStreamException("unexpected end of BDS state");
            }
        }
    }
}
