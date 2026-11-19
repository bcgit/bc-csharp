using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Signers.Xmss;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>XMSS^MT parameters (RFC 8391, NIST SP 800-208).</summary>
    public sealed class XmssMTParameters
    {
        /// <summary>
        /// The tallest hypertree whose leaves a long index can count. The per layer trees are bounded separately, and
        /// more tightly, by <see cref="XmssParameters.MaxHeight"/>.
        /// </summary>
        public const int MaxHeight = 62;

        private static readonly Dictionary<int, XmssMTParameters> ParamsLookupTable = CreateLookupTable();

        private readonly int m_parameterSetOid;
        private readonly XmssParameters m_xmssParams;
        private readonly int m_height;
        private readonly int m_layers;

        private static Dictionary<int, XmssMTParameters> CreateLookupTable()
        {
            var pMap = new Dictionary<int, XmssMTParameters>();

            // RFC 8391
            AddFamily(pMap, 0x00000001, NistObjectIdentifiers.IdSha256, -1);
            AddFamily(pMap, 0x00000009, NistObjectIdentifiers.IdSha512, -1);
            AddFamily(pMap, 0x00000011, NistObjectIdentifiers.IdShake128, -1);
            AddFamily(pMap, 0x00000019, NistObjectIdentifiers.IdShake256, -1);

            // SP 800-208: SHA-256/192 (n=24)
            AddFamily(pMap, 0x00000021, NistObjectIdentifiers.IdSha256, 24);

            // SP 800-208: SHAKE256/256 (n=32)
            AddFamily(pMap, 0x00000029, NistObjectIdentifiers.IdShake256Len, 32);

            // SP 800-208: SHAKE256/192 (n=24)
            AddFamily(pMap, 0x00000031, NistObjectIdentifiers.IdShake256Len, 24);

            return pMap;
        }

        /// <summary>
        /// The eight hypertree shapes every digest family registers, in the order their identifiers run: 20/2, 20/4,
        /// 40/2, 40/4, 40/8, 60/3, 60/6 and 60/12.
        /// </summary>
        /// <param name="n">the security parameter, or -1 for the digest's own output size.</param>
        private static void AddFamily(Dictionary<int, XmssMTParameters> pMap, int firstOid,
            DerObjectIdentifier treeDigestOid, int n)
        {
            int[] heights = { 20, 20, 40, 40, 40, 60, 60, 60 };
            int[] layers = { 2, 4, 2, 4, 8, 3, 6, 12 };

            for (int i = 0; i != heights.Length; i++)
            {
                pMap.Add(firstOid + i, new XmssMTParameters(heights[i], layers[i], treeDigestOid, n));
            }
        }

        /// <summary>XMSS^MT constructor.</summary>
        /// <param name="height">Height of tree.</param>
        /// <param name="layers">Amount of layers.</param>
        /// <param name="treeDigest">Digest to use.</param>
        public XmssMTParameters(int height, int layers, IDigest treeDigest)
            : this(height, layers, XmssDigestUtilities.GetDigestOid(
                (treeDigest ?? throw new ArgumentNullException(nameof(treeDigest))).AlgorithmName))
        {
        }

        /// <summary>XMSS^MT constructor.</summary>
        /// <param name="height">Height of tree.</param>
        /// <param name="layers">Amount of layers.</param>
        /// <param name="treeDigestOid">Object identifier of digest to use.</param>
        public XmssMTParameters(int height, int layers, DerObjectIdentifier treeDigestOid)
            : this(height, layers, treeDigestOid, -1)
        {
        }

        /// <summary>XMSS^MT constructor with explicit security parameter n.</summary>
        /// <param name="height">Height of tree.</param>
        /// <param name="layers">Amount of layers.</param>
        /// <param name="treeDigestOid">Object identifier of digest to use.</param>
        /// <param name="n">Security parameter (digest output size in bytes), or -1 to derive from digest.</param>
        public XmssMTParameters(int height, int layers, DerObjectIdentifier treeDigestOid, int n)
        {
            m_height = height;
            m_layers = layers;
            m_xmssParams = new XmssParameters(XmssTreeHeight(height, layers), treeDigestOid, n);
            m_parameterSetOid = XmssEngine.LookupXmssMTOid(TreeDigest, TreeDigestSize, WinternitzParameter, Len,
                Height, layers);
        }

        private static int XmssTreeHeight(int height, int layers)
        {
            if (height < 2)
                throw new ArgumentException("totalHeight must be > 1");
            // the one time key index across the whole hypertree is a long, and the index checks bound it by
            // comparing against 1L << totalHeight, so a total height past this leaves that shift negative or
            // wrapped: every index reads as invalid at 63, and at 64 the maximum index comes out as 0
            if (height > MaxHeight)
                throw new ArgumentException("totalHeight must be <= " + MaxHeight);
            // layers is a divisor below, and a zero one would be a DivideByZeroException rather than a report of the
            // parameter that was wrong; a negative one divides to a negative height, which would then be complained
            // about as a height
            if (layers < 1)
                throw new ArgumentException("layers must be >= 1");
            if (height % layers != 0)
                throw new ArgumentException("layers must divide totalHeight without remainder");
            if (height / layers == 1)
                throw new ArgumentException("height / layers must be greater than 1");

            return height / layers;
        }

        /// <summary>The total height of the hypertree.</summary>
        public int Height => m_height;

        /// <summary>The number of layers the hypertree is divided into.</summary>
        public int Layers => m_layers;

        /// <summary>The parameters of a single layer's tree.</summary>
        public XmssParameters XmssParameters => m_xmssParams;

        /// <summary>The name of the digest used to build the trees.</summary>
        public string TreeDigest => m_xmssParams.TreeDigest;

        /// <summary>The digest size, the security parameter n in bytes.</summary>
        public int TreeDigestSize => m_xmssParams.TreeDigestSize;

        /// <summary>The OID of the digest used to build the trees.</summary>
        public DerObjectIdentifier TreeDigestOid => m_xmssParams.TreeDigestOid;

        /// <summary>
        /// The RFC 8391 / SP 800-208 parameter-set identifier for this parameter set (the 4-octet value carried at
        /// the start of an RFC 9802 encoded key), or 0 if these parameters do not correspond to a standard set (for
        /// example a non-standard tree height).
        /// </summary>
        public int ParameterSetOid => m_parameterSetOid;

        /// <summary>The Winternitz parameter.</summary>
        public int WinternitzParameter => m_xmssParams.WinternitzParameter;

        /// <summary>The number of n-byte elements in a WOTS+ signature.</summary>
        public int Len => m_xmssParams.Len;

        /// <summary>The parameters registered under an RFC 8391 / SP 800-208 parameter-set identifier.</summary>
        /// <param name="oid">the 4-octet parameter-set identifier.</param>
        /// <returns>the parameters, or null if the identifier is not one of the registered XMSS^MT sets.</returns>
        public static XmssMTParameters LookupByOid(int oid) =>
            ParamsLookupTable.TryGetValue(oid, out var parameters) ? parameters : null;
    }
}
