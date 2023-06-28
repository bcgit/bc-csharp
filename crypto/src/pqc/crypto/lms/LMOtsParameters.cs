using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMOtsParameters
    {
        // TODO add all parameter sets

        //public static int reserved = 0;
        public static LMOtsParameters sha256_n32_w1 = new LMOtsParameters(1, 32, 1, 265, 7, 8516, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n32_w2 = new LMOtsParameters(2, 32, 2, 133, 6, 4292, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n32_w4 = new LMOtsParameters(3, 32, 4, 67, 4, 2180, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n32_w8 = new LMOtsParameters(4, 32, 8, 34, 0, 1124, NistObjectIdentifiers.IdSha256);

        private static Dictionary<object, LMOtsParameters> Suppliers = new Dictionary<object, LMOtsParameters>
        {
            { sha256_n32_w1.ID, sha256_n32_w1 },
            { sha256_n32_w2.ID, sha256_n32_w2 },
            { sha256_n32_w4.ID, sha256_n32_w4 },
            { sha256_n32_w8.ID, sha256_n32_w8 }
        };

        private readonly int m_id;
        private readonly int m_n;
        private readonly int m_w;
        private readonly int m_p;
        private readonly int m_ls;
        private readonly uint m_sigLen;
        private readonly DerObjectIdentifier m_digestOid;

        internal LMOtsParameters(int id, int n, int w, int p, int ls, uint sigLen, DerObjectIdentifier digestOid)
        {
            m_id = id;
            m_n = n;
            m_w = w;
            m_p = p;
            m_ls = ls;
            m_sigLen = sigLen;
            m_digestOid = digestOid;
        }

        public int ID => m_id;

        public int N => m_n;

        public int W => m_w;

        public int P => m_p;

        public int Ls => m_ls;

        public int SigLen => Convert.ToInt32(m_sigLen);

        public DerObjectIdentifier DigestOid => m_digestOid;

        public static LMOtsParameters GetParametersByID(int id)
        {
            return CollectionUtilities.GetValueOrNull(Suppliers, id);
        }
    }
}
