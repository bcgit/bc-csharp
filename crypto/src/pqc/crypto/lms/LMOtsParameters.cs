using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMOtsParameters
    {
        public static LMOtsParameters sha256_n32_w1 = new LMOtsParameters(1, 32, 1, 265, 7, 8516, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n32_w2 = new LMOtsParameters(2, 32, 2, 133, 6, 4292, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n32_w4 = new LMOtsParameters(3, 32, 4, 67, 4, 2180, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n32_w8 = new LMOtsParameters(4, 32, 8, 34, 0, 1124, NistObjectIdentifiers.IdSha256);

        public static LMOtsParameters sha256_n24_w1 = new LMOtsParameters(5, 24, 1, 200, 8, 5436, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n24_w2 = new LMOtsParameters(6, 24, 2, 101, 6, 2940, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n24_w4 = new LMOtsParameters(7, 24, 4, 51, 4, 1500, NistObjectIdentifiers.IdSha256);
        public static LMOtsParameters sha256_n24_w8 = new LMOtsParameters(8, 24, 8, 26, 0, 1020, NistObjectIdentifiers.IdSha256);

        public static LMOtsParameters shake256_n32_w1 = new LMOtsParameters(9, 32, 1, 265, 7, 8516, NistObjectIdentifiers.IdShake256Len);
        public static LMOtsParameters shake256_n32_w2 = new LMOtsParameters(10, 32, 2, 133, 6, 4292, NistObjectIdentifiers.IdShake256Len);
        public static LMOtsParameters shake256_n32_w4 = new LMOtsParameters(11, 32, 4, 67, 4, 2180, NistObjectIdentifiers.IdShake256Len);
        public static LMOtsParameters shake256_n32_w8 = new LMOtsParameters(12, 32, 8, 34, 0, 1124, NistObjectIdentifiers.IdShake256Len);

        public static LMOtsParameters shake256_n24_w1 = new LMOtsParameters(13, 24, 1, 200, 8, 5436, NistObjectIdentifiers.IdShake256Len);
        public static LMOtsParameters shake256_n24_w2 = new LMOtsParameters(14, 24, 2, 101, 6, 2940, NistObjectIdentifiers.IdShake256Len);
        public static LMOtsParameters shake256_n24_w4 = new LMOtsParameters(15, 24, 4, 51, 4, 1500, NistObjectIdentifiers.IdShake256Len);
        public static LMOtsParameters shake256_n24_w8 = new LMOtsParameters(16, 24, 8, 26, 0, 1020, NistObjectIdentifiers.IdShake256Len);

        private static Dictionary<object, LMOtsParameters> Suppliers = new Dictionary<object, LMOtsParameters>
        {
            { sha256_n32_w1.ID, sha256_n32_w1 },
            { sha256_n32_w2.ID, sha256_n32_w2 },
            { sha256_n32_w4.ID, sha256_n32_w4 },
            { sha256_n32_w8.ID, sha256_n32_w8 },

            { sha256_n24_w1.ID, sha256_n24_w1 },
            { sha256_n24_w2.ID, sha256_n24_w2 },
            { sha256_n24_w4.ID, sha256_n24_w4 },
            { sha256_n24_w8.ID, sha256_n24_w8 },

            { shake256_n32_w1.ID, shake256_n32_w1 },
            { shake256_n32_w2.ID, shake256_n32_w2 },
            { shake256_n32_w4.ID, shake256_n32_w4 },
            { shake256_n32_w8.ID, shake256_n32_w8 },

            { shake256_n24_w1.ID, shake256_n24_w1 },
            { shake256_n24_w2.ID, shake256_n24_w2 },
            { shake256_n24_w4.ID, shake256_n24_w4 },
            { shake256_n24_w8.ID, shake256_n24_w8 },
        };

        public static LMOtsParameters GetParametersByID(int id) =>
            CollectionUtilities.GetValueOrNull(Suppliers, id);

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
    }
}
