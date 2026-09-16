using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;

using NistOids = Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMSigParameters
    {
        public static readonly LMSigParameters lms_sha256_n32_h5 = Create(5, 32, 5, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n32_h10 = Create(6, 32, 10, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n32_h15 = Create(7, 32, 15, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n32_h20 = Create(8, 32, 20, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n32_h25 = Create(9, 32, 25, NistOids.IdSha256);

        public static readonly LMSigParameters lms_sha256_n24_h5 = Create(10, 24, 5, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n24_h10 = Create(11, 24, 10, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n24_h15 = Create(12, 24, 15, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n24_h20 = Create(13, 24, 20, NistOids.IdSha256);
        public static readonly LMSigParameters lms_sha256_n24_h25 = Create(14, 24, 25, NistOids.IdSha256);

        public static readonly LMSigParameters lms_shake256_n32_h5 = Create(15, 32, 5, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n32_h10 = Create(16, 32, 10, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n32_h15 = Create(17, 32, 15, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n32_h20 = Create(18, 32, 20, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n32_h25 = Create(19, 32, 25, NistOids.IdShake256Len);

        public static readonly LMSigParameters lms_shake256_n24_h5 = Create(20, 24, 5, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n24_h10 = Create(21, 24, 10, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n24_h15 = Create(22, 24, 15, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n24_h20 = Create(23, 24, 20, NistOids.IdShake256Len);
        public static readonly LMSigParameters lms_shake256_n24_h25 = Create(24, 24, 25, NistOids.IdShake256Len);

        private static Dictionary<int, LMSigParameters> ParametersByID = new Dictionary<int, LMSigParameters>
        {
            { lms_sha256_n32_h5.ID, lms_sha256_n32_h5 },
            { lms_sha256_n32_h10.ID, lms_sha256_n32_h10 },
            { lms_sha256_n32_h15.ID, lms_sha256_n32_h15 },
            { lms_sha256_n32_h20.ID, lms_sha256_n32_h20 },
            { lms_sha256_n32_h25.ID, lms_sha256_n32_h25 },

            { lms_sha256_n24_h5.ID, lms_sha256_n24_h5 },
            { lms_sha256_n24_h10.ID, lms_sha256_n24_h10 },
            { lms_sha256_n24_h15.ID, lms_sha256_n24_h15 },
            { lms_sha256_n24_h20.ID, lms_sha256_n24_h20 },
            { lms_sha256_n24_h25.ID, lms_sha256_n24_h25 },

            { lms_shake256_n32_h5.ID, lms_shake256_n32_h5 },
            { lms_shake256_n32_h10.ID, lms_shake256_n32_h10 },
            { lms_shake256_n32_h15.ID, lms_shake256_n32_h15 },
            { lms_shake256_n32_h20.ID, lms_shake256_n32_h20 },
            { lms_shake256_n32_h25.ID, lms_shake256_n32_h25 },

            { lms_shake256_n24_h5.ID, lms_shake256_n24_h5 },
            { lms_shake256_n24_h10.ID, lms_shake256_n24_h10 },
            { lms_shake256_n24_h15.ID, lms_shake256_n24_h15 },
            { lms_shake256_n24_h20.ID, lms_shake256_n24_h20 },
            { lms_shake256_n24_h25.ID, lms_shake256_n24_h25 },
        };

        public static LMSigParameters GetParametersByID(int id) =>
            CollectionUtilities.GetValueOrNull(ParametersByID, id);

        internal static LMSigParameters ParseByID(BinaryReader binaryReader)
        {
            int id = BinaryReaders.ReadInt32BigEndian(binaryReader);
            if (!ParametersByID.TryGetValue(id, out var parameters))
                throw new IOException($"unknown LMS type code: {id}");
            return parameters;
        }

        private static LMSigParameters Create(int id, int m, int h, DerObjectIdentifier digestOid) =>
            new LMSigParameters(id, m, h, digestOid);

        private readonly int m_id;
        private readonly int m_m;
        private readonly int m_h;
        private readonly DerObjectIdentifier m_digestOid;

        private LMSigParameters(int id, int m, int h, DerObjectIdentifier digestOid)
        {
            m_id = id;
            m_m = m;
            m_h = h;
            m_digestOid = digestOid;
        }

        /// <summary>The typecode identifies the parameter set: the rest of the values are derived from it.</summary>
        /// <remarks>
        /// The instances are interned - the constructor is private and every lookup hands back one of the static
        /// fields - so this agrees with the reference equality it replaces. It states the intent instead of
        /// leaving callers to rely on the interning.
        /// </remarks>
        public override bool Equals(object obj) => obj is LMSigParameters that && m_id == that.m_id;

        public override int GetHashCode() => m_id;

        // TODO[api] Expand to an AlgorithmIdentifier at promotion. A digest OID alone identifies the hash
        // function only where the parameters are absent; id_shake256_len carries its output length in bits as a
        // mandatory parameter (RFC 8702), so the OID here is the same for the m=24 and m=32 sets and M has to be
        // compared alongside it to tell one hash function from another.
        public DerObjectIdentifier DigestOid => m_digestOid;

        public int H => m_h;

        public int ID => m_id;

        public int M => m_m;
    }
}
