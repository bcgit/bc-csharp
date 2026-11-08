using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>XMSS Signature.</summary>
    internal sealed class XmssSignature
        : XmssReducedSignature, IEncodable
    {
        private const int IndexSize = 4;

        private readonly int m_index;
        private readonly byte[] m_random;

        /// <summary>
        /// The size of the encoding <see cref="GetEncoded"/> produces for a parameter set: a four byte index and
        /// the n-byte randomizer in front of what <see cref="XmssReducedSignature"/> writes. Read as well as
        /// written through here, so <see cref="Builder.WithSignature"/> takes an encoding apart on the layout
        /// <see cref="ToByteArray"/> lays down.
        /// </summary>
        internal static int EncodedSizeOf(XmssParameters parameters) =>
            IndexSize + parameters.TreeDigestSize + XmssReducedSignature.SizeOf(parameters);

        private XmssSignature(Builder builder)
            : base(builder)
        {
            m_index = builder.m_index;
            int n = Params.TreeDigestSize;
            m_random = XmssUtilities.ValidateOrAllocate(builder.m_random, n, "random");
        }

        public byte[] GetEncoded() => ToByteArray();

        /// <remarks>
        /// The <c>With</c> methods of the reduced signature's builder are shadowed here so that a chain started on
        /// this builder stays on it and ends in an <see cref="XmssSignature"/>.
        /// </remarks>
        internal new sealed class Builder
            : XmssReducedSignature.Builder
        {
            /* optional */
            internal int m_index = 0;
            internal byte[] m_random = null;

            internal Builder(XmssParameters parameters)
                : base(parameters)
            {
            }

            internal Builder WithIndex(int val)
            {
                m_index = val;
                return this;
            }

            internal Builder WithRandom(byte[] val)
            {
                m_random = Arrays.Clone(val);
                return this;
            }

            internal new Builder WithWotsPlusSignature(byte[][] val)
            {
                base.WithWotsPlusSignature(val);
                return this;
            }

            internal new Builder WithAuthPath(IList<XmssNode> val)
            {
                base.WithAuthPath(val);
                return this;
            }

            internal Builder WithSignature(byte[] val)
            {
                if (val == null)
                    throw new ArgumentNullException(nameof(val));

                int n = m_params.TreeDigestSize;
                if (val.Length != EncodedSizeOf(m_params))
                {
                    /* an XMSS signature is a fixed-size encoding - anything longer or shorter, in particular a
                     * valid signature carrying trailing data, is not a signature for these parameters (RFC 8391
                     * sec. 4.1.8). The XMSS^MT signature checks the same way. */
                    throw new ArgumentException("signature has wrong size");
                }
                int position = 0;
                /* extract index */
                m_index = (int)Pack.BE_To_UInt32(val, position);

                /* the four index bytes are read as a signed int, so an encoding that arrived from somewhere else
                 * can name a leaf this tree does not have, or a negative one. Refused here as the XMSS^MT
                 * signature refuses it, rather than left to fail further in. IsIndexValid raises rather than
                 * returns for the negative case. */
                if (!XmssUtilities.IsIndexValid(m_params.Height, m_index))
                    throw new ArgumentException("index out of bounds");

                position += IndexSize;
                /* extract random */
                m_random = Arrays.CopyOfRange(val, position, position + n);
                position += n;
                WithReducedSignature(val, position);
                return this;
            }

            internal new XmssSignature Build() => new XmssSignature(this);
        }

        internal override byte[] ToByteArray()
        {
            /* index || random || signature || authentication path */
            int n = Params.TreeDigestSize;
            byte[] output = new byte[EncodedSizeOf(Params)];
            int position = 0;
            /* copy index */
            Pack.UInt32_To_BE((uint)m_index, output, position);
            position += IndexSize;
            /* copy random */
            Array.Copy(m_random, 0, output, position, m_random.Length);
            position += n;
            /* copy signature || authentication path */
            EncodeTo(output, position);
            return output;
        }

        internal int Index => m_index;

        /// <summary>
        /// This signature's randomizer r, by reference. The engine is the only caller and copies it straight into
        /// the H_msg key it builds; a new caller must not write to what it gets back.
        /// </summary>
        internal byte[] GetRandom() => m_random;
    }
}
