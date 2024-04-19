using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMSigParameters
    {
        public static LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(5, 32, 5, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(6, 32, 10, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(7, 32, 15, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(8, 32, 20, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(9, 32, 25, NistObjectIdentifiers.IdSha256);

        public static LMSigParameters lms_sha256_n24_h5 = new LMSigParameters(10, 24, 5, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n24_h10 = new LMSigParameters(11, 24, 10, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n24_h15 = new LMSigParameters(12, 24, 15, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n24_h20 = new LMSigParameters(13, 24, 20, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n24_h25 = new LMSigParameters(14, 24, 25, NistObjectIdentifiers.IdSha256);

        public static LMSigParameters lms_shake256_n32_h5 = new LMSigParameters(15, 32, 5, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n32_h10 = new LMSigParameters(16, 32, 10, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n32_h15 = new LMSigParameters(17, 32, 15, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n32_h20 = new LMSigParameters(18, 32, 20, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n32_h25 = new LMSigParameters(19, 32, 25, NistObjectIdentifiers.IdShake256Len);

        public static LMSigParameters lms_shake256_n24_h5 = new LMSigParameters(20, 24, 5, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n24_h10 = new LMSigParameters(21, 24, 10, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n24_h15 = new LMSigParameters(22, 24, 15, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n24_h20 = new LMSigParameters(23, 24, 20, NistObjectIdentifiers.IdShake256Len);
        public static LMSigParameters lms_shake256_n24_h25 = new LMSigParameters(24, 24, 25, NistObjectIdentifiers.IdShake256Len);

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
                throw new InvalidDataException($"unknown LMSigParameters {id}");
            return parameters;
        }

        private readonly int m_id;
        private readonly int m_m;
        private readonly int m_h;
        private readonly DerObjectIdentifier m_digestOid;

        internal LMSigParameters(int id, int m, int h, DerObjectIdentifier digestOid)
        {
            m_id = id;
            m_m = m;
            m_h = h;
            m_digestOid = digestOid;
        }

        public DerObjectIdentifier DigestOid => m_digestOid;

        public int H => m_h;

        public int ID => m_id;

        public int M => m_m;
    }
}
