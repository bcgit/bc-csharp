using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>XMSS^MT Signature.</summary>
    internal sealed class XmssMTSignature
        : IEncodable
    {
        private readonly XmssMTParameters m_params;
        private readonly long m_index;
        private readonly byte[] m_random;
        private readonly List<XmssReducedSignature> m_reducedSignatures;

        /// <summary>
        /// The width of the index field: the fewest whole bytes that hold a leaf index of a hypertree of this
        /// height. The private key encoding measures its own index field the same way, in XmssPrivateKeyCodec.
        /// </summary>
        internal static int IndexSizeOf(XmssMTParameters parameters) => (parameters.Height + 7) / 8;

        /// <summary>
        /// The size of the encoding <see cref="ToByteArray"/> produces for a parameter set: the index and the n-byte
        /// randomizer in front of one reduced signature per layer. Read as well as written through here, so the
        /// constructor takes an encoding apart on the layout <see cref="ToByteArray"/> lays down, and the per-layer
        /// size both step by is the one <see cref="XmssReducedSignature"/> measures for a single layer's tree.
        /// </summary>
        internal static int EncodedSizeOf(XmssMTParameters parameters) =>
            IndexSizeOf(parameters) + parameters.TreeDigestSize
                + XmssReducedSignature.SizeOf(parameters.XmssParameters) * parameters.Layers;

        private XmssMTSignature(Builder builder)
        {
            m_params = builder.m_params;
            int n = m_params.TreeDigestSize;
            byte[] signature = builder.m_signature;
            if (signature != null)
            {
                /* import */
                int indexSize = IndexSizeOf(m_params);
                int reducedSignatureSizeSingle = XmssReducedSignature.SizeOf(m_params.XmssParameters);
                if (signature.Length != EncodedSizeOf(m_params))
                    throw new ArgumentException("signature has wrong size");

                int position = 0;
                m_index = (long)Pack.BE_To_UInt64_Low(signature, position, indexSize);

                /* at a total height needing all eight bytes the index reads as signed, so it can be negative too;
                 * IsIndexValid raises rather than returns for that case */
                if (!XmssUtilities.IsIndexValid(m_params.Height, m_index))
                    throw new ArgumentException("index out of bounds");

                position += indexSize;
                m_random = Arrays.CopyOfRange(signature, position, position + n);
                position += n;
                m_reducedSignatures = new List<XmssReducedSignature>(m_params.Layers);
                while (position < signature.Length)
                {
                    XmssReducedSignature xmssSig = new XmssReducedSignature.Builder(m_params.XmssParameters)
                        .WithReducedSignature(signature, position)
                        .Build();
                    m_reducedSignatures.Add(xmssSig);
                    position += reducedSignatureSizeSingle;
                }
            }
            else
            {
                /* set */
                m_index = builder.m_index;
                m_random = XmssUtilities.ValidateOrAllocate(builder.m_random, n, "random");
                m_reducedSignatures = new List<XmssReducedSignature>(m_params.Layers);
            }
        }

        public byte[] GetEncoded() => ToByteArray();

        internal sealed class Builder
        {
            /* mandatory */
            internal readonly XmssMTParameters m_params;
            /* optional */
            internal long m_index = 0L;
            internal byte[] m_random = null;
            internal byte[] m_signature = null;

            internal Builder(XmssMTParameters parameters)
            {
                m_params = parameters;
            }

            internal Builder WithIndex(long val)
            {
                m_index = val;
                return this;
            }

            internal Builder WithRandom(byte[] val)
            {
                m_random = Arrays.Clone(val);
                return this;
            }

            /// <remarks>
            /// An absent encoding is refused here rather than taken, as bc-java takes it, for a request to build the
            /// signature from its fields: that is what <see cref="XmssSignature.Builder.WithSignature"/> does too.
            /// </remarks>
            internal Builder WithSignature(byte[] val)
            {
                if (val == null)
                    throw new ArgumentNullException(nameof(val));

                m_signature = Arrays.Clone(val);
                return this;
            }

            internal XmssMTSignature Build() => new XmssMTSignature(this);
        }

        internal byte[] ToByteArray()
        {
            /* index || random || reduced signatures */
            int n = m_params.TreeDigestSize;
            int indexSize = IndexSizeOf(m_params);
            int reducedSignatureSizeSingle = XmssReducedSignature.SizeOf(m_params.XmssParameters);
            byte[] output = new byte[EncodedSizeOf(m_params)];
            int position = 0;
            /* copy index - indexSize is 1..8 for every height the parameters admit (2..62) */
            Pack.UInt64_To_BE_Low((ulong)m_index, output, position, indexSize);
            position += indexSize;
            /* copy random */
            Array.Copy(m_random, 0, output, position, m_random.Length);
            position += n;
            /* copy reduced signatures */
            foreach (XmssReducedSignature reducedSignature in m_reducedSignatures)
            {
                reducedSignature.EncodeTo(output, position);
                position += reducedSignatureSizeSingle;
            }
            return output;
        }

        internal long Index => m_index;

        /// <summary>
        /// This signature's randomizer r, by reference. The engine is the only caller and copies it straight into
        /// the H_msg key it builds; a new caller must not write to what it gets back.
        /// </summary>
        internal byte[] GetRandom() => m_random;

        /// <summary>
        /// The reduced signatures, one per layer from the bottom up, by reference: the engine appends each layer's
        /// as it builds the signature.
        /// </summary>
        internal IList<XmssReducedSignature> ReducedSignatures => m_reducedSignatures;
    }
}
