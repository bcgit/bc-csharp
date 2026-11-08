using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Signers.Xmss;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>XMSS parameters (RFC 8391, NIST SP 800-208).</summary>
    public sealed class XmssParameters
    {
        /// <summary>The Winternitz parameter, fixed at 16 by RFC 8391 sec. 5.</summary>
        private const int WinternitzParameterValue = 16;

        /// <summary>
        /// The tallest tree whose leaves an int index can count. A traversal state outside it is refused as well.
        /// </summary>
        public const int MaxHeight = 30;

        private static readonly Dictionary<int, XmssParameters> ParamsLookupTable = CreateLookupTable();

        private readonly int m_parameterSetOid;
        private readonly int m_height;
        private readonly int m_k;
        private readonly DerObjectIdentifier m_treeDigestOid;

        private readonly string m_treeDigest;
        private readonly int m_treeDigestSize;
        private readonly int m_len;

        private static Dictionary<int, XmssParameters> CreateLookupTable()
        {
            var pMap = new Dictionary<int, XmssParameters>();

            // RFC 8391
            pMap.Add(0x00000001, new XmssParameters(10, NistObjectIdentifiers.IdSha256));
            pMap.Add(0x00000002, new XmssParameters(16, NistObjectIdentifiers.IdSha256));
            pMap.Add(0x00000003, new XmssParameters(20, NistObjectIdentifiers.IdSha256));
            pMap.Add(0x00000004, new XmssParameters(10, NistObjectIdentifiers.IdSha512));
            pMap.Add(0x00000005, new XmssParameters(16, NistObjectIdentifiers.IdSha512));
            pMap.Add(0x00000006, new XmssParameters(20, NistObjectIdentifiers.IdSha512));
            pMap.Add(0x00000007, new XmssParameters(10, NistObjectIdentifiers.IdShake128));
            pMap.Add(0x00000008, new XmssParameters(16, NistObjectIdentifiers.IdShake128));
            pMap.Add(0x00000009, new XmssParameters(20, NistObjectIdentifiers.IdShake128));
            pMap.Add(0x0000000a, new XmssParameters(10, NistObjectIdentifiers.IdShake256));
            pMap.Add(0x0000000b, new XmssParameters(16, NistObjectIdentifiers.IdShake256));
            pMap.Add(0x0000000c, new XmssParameters(20, NistObjectIdentifiers.IdShake256));

            // SP 800-208: SHA-256/192 (n=24)
            pMap.Add(0x0000000d, new XmssParameters(10, NistObjectIdentifiers.IdSha256, 24));
            pMap.Add(0x0000000e, new XmssParameters(16, NistObjectIdentifiers.IdSha256, 24));
            pMap.Add(0x0000000f, new XmssParameters(20, NistObjectIdentifiers.IdSha256, 24));

            // SP 800-208: SHAKE256/256 (n=32)
            pMap.Add(0x00000010, new XmssParameters(10, NistObjectIdentifiers.IdShake256Len, 32));
            pMap.Add(0x00000011, new XmssParameters(16, NistObjectIdentifiers.IdShake256Len, 32));
            pMap.Add(0x00000012, new XmssParameters(20, NistObjectIdentifiers.IdShake256Len, 32));

            // SP 800-208: SHAKE256/192 (n=24)
            pMap.Add(0x00000013, new XmssParameters(10, NistObjectIdentifiers.IdShake256Len, 24));
            pMap.Add(0x00000014, new XmssParameters(16, NistObjectIdentifiers.IdShake256Len, 24));
            pMap.Add(0x00000015, new XmssParameters(20, NistObjectIdentifiers.IdShake256Len, 24));

            return pMap;
        }

        /// <summary>XMSS constructor.</summary>
        /// <param name="height">Height of tree.</param>
        /// <param name="treeDigest">Digest to use.</param>
        public XmssParameters(int height, IDigest treeDigest)
            : this(height, XmssDigestUtilities.GetDigestOid(
                (treeDigest ?? throw new ArgumentNullException(nameof(treeDigest))).AlgorithmName))
        {
        }

        /// <summary>XMSS constructor.</summary>
        /// <param name="height">Height of tree.</param>
        /// <param name="treeDigestOid">OID of digest to use.</param>
        public XmssParameters(int height, DerObjectIdentifier treeDigestOid)
            : this(height, treeDigestOid, -1)
        {
        }

        /// <summary>XMSS constructor with explicit security parameter n.</summary>
        /// <param name="height">Height of tree.</param>
        /// <param name="treeDigestOid">OID of digest to use.</param>
        /// <param name="n">Security parameter (digest output size in bytes), or -1 to derive from digest.</param>
        public XmssParameters(int height, DerObjectIdentifier treeDigestOid, int n)
        {
            if (height < 2)
                throw new ArgumentException("height must be >= 2");
            // the one time key index, and the maximum index bounding it, are both ints, so a tree taller than this
            // cannot count its own leaves: (1 << height) - 1 wraps. The BDS state validation refuses a state outside
            // the same bound on the way back in.
            if (height > MaxHeight)
                throw new ArgumentException("height must be <= " + MaxHeight);
            if (treeDigestOid == null)
                throw new ArgumentNullException(nameof(treeDigestOid), "digest == null");

            m_height = height;
            m_k = DetermineMinK();
            m_treeDigest = XmssDigestUtilities.GetDigestName(treeDigestOid);
            m_treeDigestOid = treeDigestOid;

            m_treeDigestSize = (n > 0) ? n : XmssDigestUtilities.GetDigestSize(treeDigestOid);
            m_len = new WotsPlusParameters(treeDigestOid, m_treeDigestSize).Len;
            DefaultXmssOid oid = DefaultXmssOid.Lookup(m_treeDigest, m_treeDigestSize, WinternitzParameterValue,
                m_len, height);
            m_parameterSetOid = (oid != null) ? oid.Oid : 0;
        }

        private int DetermineMinK()
        {
            for (int k = 2; k <= m_height; k++)
            {
                if ((m_height - k) % 2 == 0)
                    return k;
            }
            throw new InvalidOperationException("should never happen...");
        }

        /// <summary>The digest size, the security parameter n in bytes.</summary>
        public int TreeDigestSize => m_treeDigestSize;

        /// <summary>The OID of the digest used to build the tree.</summary>
        public DerObjectIdentifier TreeDigestOid => m_treeDigestOid;

        /// <summary>
        /// The RFC 8391 / SP 800-208 parameter-set identifier for this parameter set (the 4-octet value carried at
        /// the start of an RFC 9802 encoded key), or 0 if these parameters do not correspond to a standard set (for
        /// example a non-standard tree height).
        /// </summary>
        public int ParameterSetOid => m_parameterSetOid;

        /// <summary>The XMSS tree height.</summary>
        public int Height => m_height;

        /// <summary>The name of the digest used to build the tree.</summary>
        public string TreeDigest => m_treeDigest;

        /// <summary>The number of n-byte elements in a WOTS+ signature.</summary>
        public int Len => m_len;

        /// <summary>The Winternitz parameter.</summary>
        public int WinternitzParameter => WinternitzParameterValue;

        /// <summary>The BDS traversal parameter k.</summary>
        public int K => m_k;

        /// <summary>The parameters registered under an RFC 8391 / SP 800-208 parameter-set identifier.</summary>
        /// <param name="oid">the 4-octet parameter-set identifier.</param>
        /// <returns>the parameters, or null if the identifier is not one of the registered XMSS sets.</returns>
        public static XmssParameters LookupByOid(int oid) =>
            ParamsLookupTable.TryGetValue(oid, out var parameters) ? parameters : null;
    }
}
