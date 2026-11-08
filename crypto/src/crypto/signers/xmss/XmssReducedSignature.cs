using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>Reduced XMSS Signature.</summary>
    internal class XmssReducedSignature
    {
        private readonly XmssParameters m_params;
        private readonly byte[][] m_wotsPlusSignature;
        private readonly IList<XmssNode> m_authPath;

        /// <summary>
        /// The size of the encoding <see cref="ToByteArray"/> produces for a parameter set: the len n-byte WOTS+
        /// blocks followed by the h authentication path nodes. Read as well as written through here, so the layout
        /// the constructor takes an encoding apart on is the one <see cref="ToByteArray"/> and
        /// <see cref="EncodeTo"/> lay down. XmssSignature puts its own head in front of this size and the XMSS^MT
        /// signature takes it once per layer, both from here.
        /// </summary>
        internal static int SizeOf(XmssParameters parameters) =>
            (parameters.Len + parameters.Height) * parameters.TreeDigestSize;

        internal XmssReducedSignature(Builder builder)
        {
            m_params = builder.m_params;
            int n = m_params.TreeDigestSize;
            int len = m_params.Len;
            int height = m_params.Height;
            byte[] reducedSignature = builder.m_reducedSignature;
            if (reducedSignature != null)
            {
                /* import */
                int position = builder.m_reducedSignatureOff;
                if (position < 0 || SizeOf(m_params) > reducedSignature.Length - position)
                    throw new ArgumentException("signature has wrong size");

                byte[][] wotsPlusSignature = new byte[len][];
                for (int i = 0; i < wotsPlusSignature.Length; i++)
                {
                    wotsPlusSignature[i] = Arrays.CopyOfRange(reducedSignature, position, position + n);
                    position += n;
                }
                m_wotsPlusSignature = wotsPlusSignature;

                List<XmssNode> nodeList = new List<XmssNode>(height);
                for (int i = 0; i < height; i++)
                {
                    nodeList.Add(new XmssNode(i, Arrays.CopyOfRange(reducedSignature, position, position + n)));
                    position += n;
                }
                m_authPath = nodeList;
            }
            else
            {
                /* set */
                byte[][] tmpSignature = builder.m_wotsPlusSignature;
                if (tmpSignature != null)
                {
                    m_wotsPlusSignature = tmpSignature;
                }
                else
                {
                    m_wotsPlusSignature = new byte[len][];
                    for (int i = 0; i < len; i++)
                    {
                        m_wotsPlusSignature[i] = new byte[n];
                    }
                }
                IList<XmssNode> tmpAuthPath = builder.m_authPath;
                if (tmpAuthPath != null)
                {
                    if (tmpAuthPath.Count != height)
                        throw new ArgumentException("size of authPath needs to be equal to height of tree");

                    m_authPath = tmpAuthPath;
                }
                else
                {
                    m_authPath = new List<XmssNode>();
                }
            }
        }

        internal class Builder
        {
            /* mandatory */
            internal readonly XmssParameters m_params;
            /* optional */
            internal byte[][] m_wotsPlusSignature = null;
            internal IList<XmssNode> m_authPath = null;
            internal byte[] m_reducedSignature = null;
            internal int m_reducedSignatureOff = 0;

            internal Builder(XmssParameters parameters)
            {
                m_params = parameters;
            }

            internal Builder WithWotsPlusSignature(byte[][] val)
            {
                m_wotsPlusSignature = val;
                return this;
            }

            internal Builder WithAuthPath(IList<XmssNode> val)
            {
                m_authPath = val;
                return this;
            }

            /// <summary>
            /// Read signature || authentication path out of <paramref name="input"/> starting at
            /// <paramref name="position"/>, the read side of <see cref="EncodeTo"/>.
            /// </summary>
            /// <remarks>
            /// At an offset, rather than out of an array of its own, because that is the shape both callers are
            /// in: an XMSS signature encoding puts index || random in front of one of these and an XMSS^MT encoding
            /// lays down one per layer. Nothing of <paramref name="input"/> is retained, so the caller keeps it;
            /// but it is read at <see cref="Build"/> rather than here, so a builder must not be held across a write
            /// to it.
            /// </remarks>
            /// <param name="input">the encoding to read from.</param>
            /// <param name="position">where in it this reduced signature starts.</param>
            internal Builder WithReducedSignature(byte[] input, int position)
            {
                m_reducedSignature = input;
                m_reducedSignatureOff = position;
                return this;
            }

            internal XmssReducedSignature Build() => new XmssReducedSignature(this);
        }

        internal virtual byte[] ToByteArray()
        {
            /* signature || authentication path */
            byte[] output = new byte[SizeOf(m_params)];
            EncodeTo(output, 0);
            return output;
        }

        /// <summary>
        /// Write signature || authentication path into <paramref name="output"/> at <paramref name="position"/>.
        /// </summary>
        /// <remarks>
        /// The encodings that carry one of these are filling a buffer of their own - XmssSignature puts
        /// index || random in front of it, the XMSS^MT signature lays one down per layer - so writing into the
        /// caller's buffer keeps a per-signature array out of the encoding.
        /// </remarks>
        internal void EncodeTo(byte[] output, int position)
        {
            int n = m_params.TreeDigestSize;
            /* copy signature */
            for (int i = 0; i < m_wotsPlusSignature.Length; i++)
            {
                Array.Copy(m_wotsPlusSignature[i], 0, output, position, n);
                position += n;
            }
            /* copy authentication path */
            for (int i = 0; i < m_authPath.Count; i++)
            {
                m_authPath[i].EncodeTo(output, position);
                position += n;
            }
        }

        internal XmssParameters Params => m_params;

        /// <summary>
        /// This signature's len n-byte WOTS+ blocks, by reference. The one caller chains from them and writes to
        /// neither the array nor a block of it, so handing them over lets nothing escape - the same terms
        /// <see cref="EncodeTo"/> reads them on.
        /// </summary>
        internal byte[][] GetWotsPlusSignature() => m_wotsPlusSignature;

        internal IList<XmssNode> AuthPath => m_authPath;
    }
}
