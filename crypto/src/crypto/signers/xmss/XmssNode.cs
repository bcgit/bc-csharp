using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>Binary tree node.</summary>
    internal sealed class XmssNode
    {
        private readonly int m_height;
        private readonly byte[] m_value;

        internal XmssNode(int height, byte[] value)
        {
            m_height = height;
            m_value = value;
        }

        internal int Height => m_height;

        internal byte[] GetValue() => Arrays.Clone(m_value);

        /// <summary>
        /// Write this node's value into <paramref name="output"/> at <paramref name="position"/>, without the
        /// defensive copy <see cref="GetValue"/> makes.
        /// </summary>
        internal void EncodeTo(byte[] output, int position) =>
            Array.Copy(m_value, 0, output, position, m_value.Length);

        /// <summary>
        /// The length of this node's value, for a caller that needs it before writing the value out.
        /// </summary>
        internal int ValueLength => m_value.Length;

        /// <summary>Whether this node's value is present and exactly <paramref name="length"/> bytes.</summary>
        internal bool HasValueLength(int length) => m_value != null && m_value.Length == length;

        /// <summary>
        /// Write this node's value to <paramref name="output"/>, without the defensive copy
        /// <see cref="GetValue"/> makes.
        /// </summary>
        internal void EncodeTo(Stream output) => output.Write(m_value, 0, m_value.Length);

        /// <summary>
        /// XOR <paramref name="length"/> bytes of this node's value into <paramref name="output"/> at
        /// <paramref name="position"/>, over the bitmask the caller has already put there.
        /// </summary>
        /// <remarks>
        /// The length is the caller's n rather than this value's own, so a node that is somehow not n bytes still
        /// fails here instead of masking fewer bytes.
        /// </remarks>
        internal void MaskInto(int length, byte[] output, int position) =>
            Bytes.XorTo(length, m_value, 0, output, position);

        /// <summary>This node's own value, one height further up the tree.</summary>
        internal XmssNode IncrementHeight() => new XmssNode(m_height + 1, m_value);
    }
}
