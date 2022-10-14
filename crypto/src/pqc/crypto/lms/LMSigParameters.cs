using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMSigParameters
    {
        public static LMSigParameters lms_sha256_n32_h5 = new LMSigParameters(5, 32, 5, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h10 = new LMSigParameters(6, 32, 10, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h15 = new LMSigParameters(7, 32, 15, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h20 = new LMSigParameters(8, 32, 20, NistObjectIdentifiers.IdSha256);
        public static LMSigParameters lms_sha256_n32_h25 = new LMSigParameters(9, 32, 25, NistObjectIdentifiers.IdSha256);

        private static Dictionary<int, LMSigParameters> ParametersByID = new Dictionary<int, LMSigParameters>
        {
            { lms_sha256_n32_h5.ID, lms_sha256_n32_h5 },
            { lms_sha256_n32_h10.ID, lms_sha256_n32_h10 },
            { lms_sha256_n32_h15.ID, lms_sha256_n32_h15 },
            { lms_sha256_n32_h20.ID, lms_sha256_n32_h20 },
            { lms_sha256_n32_h25.ID, lms_sha256_n32_h25 }
        };

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

        public int ID => m_id;

        public int H => m_h;

        public int M => m_m;

        public DerObjectIdentifier DigestOid => m_digestOid;

        public static LMSigParameters GetParametersByID(int id)
        {
            return CollectionUtilities.GetValueOrNull(ParametersByID, id);
        }
    }
}
