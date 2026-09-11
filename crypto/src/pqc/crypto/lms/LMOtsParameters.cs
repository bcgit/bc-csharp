using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;

using NistOids = Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMOtsParameters
    {
        public static readonly LMOtsParameters sha256_n32_w1 = Create(1, 32, 1, NistOids.IdSha256);
        public static readonly LMOtsParameters sha256_n32_w2 = Create(2, 32, 2, NistOids.IdSha256);
        public static readonly LMOtsParameters sha256_n32_w4 = Create(3, 32, 4, NistOids.IdSha256);
        public static readonly LMOtsParameters sha256_n32_w8 = Create(4, 32, 8, NistOids.IdSha256);

        public static readonly LMOtsParameters sha256_n24_w1 = Create(5, 24, 1, NistOids.IdSha256);
        public static readonly LMOtsParameters sha256_n24_w2 = Create(6, 24, 2, NistOids.IdSha256);
        public static readonly LMOtsParameters sha256_n24_w4 = Create(7, 24, 4, NistOids.IdSha256);
        public static readonly LMOtsParameters sha256_n24_w8 = Create(8, 24, 8, NistOids.IdSha256);

        public static readonly LMOtsParameters shake256_n32_w1 = Create(9, 32, 1, NistOids.IdShake256Len);
        public static readonly LMOtsParameters shake256_n32_w2 = Create(10, 32, 2, NistOids.IdShake256Len);
        public static readonly LMOtsParameters shake256_n32_w4 = Create(11, 32, 4, NistOids.IdShake256Len);
        public static readonly LMOtsParameters shake256_n32_w8 = Create(12, 32, 8, NistOids.IdShake256Len);

        public static readonly LMOtsParameters shake256_n24_w1 = Create(13, 24, 1, NistOids.IdShake256Len);
        public static readonly LMOtsParameters shake256_n24_w2 = Create(14, 24, 2, NistOids.IdShake256Len);
        public static readonly LMOtsParameters shake256_n24_w4 = Create(15, 24, 4, NistOids.IdShake256Len);
        public static readonly LMOtsParameters shake256_n24_w8 = Create(16, 24, 8, NistOids.IdShake256Len);

        private static Dictionary<int, LMOtsParameters> ParametersByID = new Dictionary<int, LMOtsParameters>
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
            CollectionUtilities.GetValueOrNull(ParametersByID, id);

        internal static LMOtsParameters ParseByID(BinaryReader binaryReader)
        {
            int id = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (!ParametersByID.TryGetValue(id, out var parameters))
                throw new IOException($"unknown LM-OTS type code: {id}");
            return parameters;
        }

        /// <summary>
        /// Build a parameter set from its defining values: the typecode, the hash length n and the Winternitz
        /// parameter w. The rest follows from n and w (RFC 8554 Appendix B): u = ceil(8n / w) chains carry the
        /// message digest, v = ceil((floor(log2(u * (2^w - 1))) + 1) / w) chains carry its checksum, p = u + v, the
        /// checksum is left-shifted by ls = 16 - v * w, and a signature is u32str(type) || C || y[0..p-1], i.e.
        /// 4 + n + p * n bytes.
        /// </summary>
        private static LMOtsParameters Create(int id, int n, int w, DerObjectIdentifier digestOid)
        {
            int u = (8 * n + w - 1) / w;
            int v = (Integers.BitLength(u * ((1 << w) - 1)) + w - 1) / w; // BitLength(x) == floor(log2(x)) + 1
            int p = u + v;
            int ls = 16 - v * w;
            int sigLen = 4 + n + p * n;

            return new LMOtsParameters(id, n, w, p, ls, sigLen, digestOid);
        }

        private readonly int m_id;
        private readonly int m_n;
        private readonly int m_w;
        private readonly int m_p;
        private readonly int m_ls;
        private readonly int m_sigLen;
        private readonly DerObjectIdentifier m_digestOid;

        private LMOtsParameters(int id, int n, int w, int p, int ls, int sigLen, DerObjectIdentifier digestOid)
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

        public int SigLen => m_sigLen;

        public DerObjectIdentifier DigestOid => m_digestOid;
    }
}
