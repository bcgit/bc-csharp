using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>WOTS+ Parameters.</summary>
    internal sealed class WotsPlusParameters
    {
        /// <summary>
        /// The Winternitz parameter, fixed at 16 by RFC 8391 sec. 5. No parameter set varies it.
        /// </summary>
        internal const int WinternitzParameter = 16;

        /// <summary>The message digest size.</summary>
        private readonly int m_digestSize;
        /// <summary>The number of n-byte string elements in a WOTS+ secret key, public key, and signature.</summary>
        private readonly int m_len;
        private readonly int m_len1;
        private readonly int m_len2;
        private readonly DerObjectIdentifier m_treeDigest;

        /// <param name="treeDigest">The digest used for WOTS+.</param>
        internal WotsPlusParameters(DerObjectIdentifier treeDigest)
            : this(treeDigest, XmssDigestUtilities.GetDigestSize(treeDigest))
        {
        }

        /// <summary>Constructor with explicit digest size (security parameter n).</summary>
        /// <param name="treeDigest">The digest used for WOTS+.</param>
        /// <param name="digestSize">The security parameter n in bytes.</param>
        internal WotsPlusParameters(DerObjectIdentifier treeDigest, int digestSize)
        {
            m_treeDigest = treeDigest;
            m_digestSize = digestSize;
            m_len1 = (int)System.Math.Ceiling((double)(8 * digestSize) / XmssUtilities.Log2(WinternitzParameter));
            m_len2 = (int)System.Math.Floor((double)(XmssUtilities.Log2(m_len1 * (WinternitzParameter - 1)) /
                XmssUtilities.Log2(WinternitzParameter))) + 1;
            m_len = m_len1 + m_len2;
            string algName = XmssDigestUtilities.GetDigestName(treeDigest);
            // The identifier this answers with is not kept, but whether there is one at all is the only thing that
            // rejects a security parameter no XMSS parameter set defines: len1, len2 and len above are computed
            // from whatever n is, so a SHA-256 asked for at n = 17, or truncated to 64, is stopped here.
            if (WotsPlusOid.Lookup(algName, digestSize, WinternitzParameter, m_len) == null)
                throw new ArgumentException("cannot find OID for digest algorithm: " + algName);
        }

        internal int TreeDigestSize => m_digestSize;

        internal int Len => m_len;

        internal int Len1 => m_len1;

        internal int Len2 => m_len2;

        internal DerObjectIdentifier TreeDigest => m_treeDigest;
    }
}
