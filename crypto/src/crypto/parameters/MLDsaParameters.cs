using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaParameters
    {
        public static readonly MLDsaParameters ML_DSA_44 = new MLDsaParameters("ML-DSA-44", 2,
            NistObjectIdentifiers.id_ml_dsa_44);
        public static readonly MLDsaParameters ML_DSA_65 = new MLDsaParameters("ML-DSA-65", 3,
            NistObjectIdentifiers.id_ml_dsa_65);
        public static readonly MLDsaParameters ML_DSA_87 = new MLDsaParameters("ML-DSA-87", 5,
            NistObjectIdentifiers.id_ml_dsa_87);

        private static readonly Dictionary<string, MLDsaParameters> ByName =
            new Dictionary<string, MLDsaParameters>()
        {
            { MLDsaParameters.ML_DSA_44.Name, MLDsaParameters.ML_DSA_44 },
            { MLDsaParameters.ML_DSA_65.Name, MLDsaParameters.ML_DSA_65 },
            { MLDsaParameters.ML_DSA_87.Name, MLDsaParameters.ML_DSA_87 },
        };

        private static readonly Dictionary<DerObjectIdentifier, MLDsaParameters> ByOid =
            new Dictionary<DerObjectIdentifier, MLDsaParameters>()
        {
            { MLDsaParameters.ML_DSA_44.Oid, MLDsaParameters.ML_DSA_44 },
            { MLDsaParameters.ML_DSA_65.Oid, MLDsaParameters.ML_DSA_65 },
            { MLDsaParameters.ML_DSA_87.Oid, MLDsaParameters.ML_DSA_87 },
        };

        internal static MLDsaParameters FromName(string name) => CollectionUtilities.GetValueOrNull(ByName, name);

        internal static MLDsaParameters FromOid(DerObjectIdentifier oid) =>
            CollectionUtilities.GetValueOrNull(ByOid, oid);

        private readonly string m_name;
        private readonly int m_mode;
        private readonly DerObjectIdentifier m_oid;

        private MLDsaParameters(string name, int mode, DerObjectIdentifier oid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_mode = mode;
            m_oid = oid;
        }

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        internal DilithiumEngine GetEngine(SecureRandom random) =>
            new DilithiumEngine(m_mode, random, usingAes: false);
    }
}
