using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaParameters
    {
        public static readonly MLDsaParameters ml_dsa_44 = new MLDsaParameters("ML-DSA-44", MLDsaParameterSet.ml_dsa_44,
            NistObjectIdentifiers.id_ml_dsa_44, null);
        public static readonly MLDsaParameters ml_dsa_65 = new MLDsaParameters("ML-DSA-65", MLDsaParameterSet.ml_dsa_65,
            NistObjectIdentifiers.id_ml_dsa_65, null);
        public static readonly MLDsaParameters ml_dsa_87 = new MLDsaParameters("ML-DSA-87", MLDsaParameterSet.ml_dsa_87,
            NistObjectIdentifiers.id_ml_dsa_87, null);

        public static readonly MLDsaParameters ml_dsa_44_with_sha512 = new MLDsaParameters("ML-DSA-44-WITH-SHA512",
            MLDsaParameterSet.ml_dsa_44, NistObjectIdentifiers.id_hash_ml_dsa_44_with_sha512,
            NistObjectIdentifiers.IdSha512);
        public static readonly MLDsaParameters ml_dsa_65_with_sha512 = new MLDsaParameters("ML-DSA-65-WITH-SHA512",
            MLDsaParameterSet.ml_dsa_65, NistObjectIdentifiers.id_hash_ml_dsa_65_with_sha512,
            NistObjectIdentifiers.IdSha512);
        public static readonly MLDsaParameters ml_dsa_87_with_sha512 = new MLDsaParameters("ML-DSA-87-WITH-SHA512",
            MLDsaParameterSet.ml_dsa_87, NistObjectIdentifiers.id_hash_ml_dsa_87_with_sha512,
            NistObjectIdentifiers.IdSha512);

        internal static readonly IDictionary<string, MLDsaParameters> ByName = CollectionUtilities.ReadOnly(
            new Dictionary<string, MLDsaParameters>()
        {
            { ml_dsa_44.Name, ml_dsa_44 },
            { ml_dsa_44_with_sha512.Name, ml_dsa_44_with_sha512 },
            { ml_dsa_65.Name, ml_dsa_65 },
            { ml_dsa_65_with_sha512.Name, ml_dsa_65_with_sha512 },
            { ml_dsa_87.Name, ml_dsa_87 },
            { ml_dsa_87_with_sha512.Name, ml_dsa_87_with_sha512 },
        });

        internal static readonly IDictionary<DerObjectIdentifier, MLDsaParameters> ByOid = CollectionUtilities.ReadOnly(
            new Dictionary<DerObjectIdentifier, MLDsaParameters>()
        {
            { ml_dsa_44.Oid, ml_dsa_44 },
            { ml_dsa_44_with_sha512.Oid, ml_dsa_44_with_sha512 },
            { ml_dsa_65.Oid, ml_dsa_65 },
            { ml_dsa_65_with_sha512.Oid, ml_dsa_65_with_sha512 },
            { ml_dsa_87.Oid, ml_dsa_87 },
            { ml_dsa_87_with_sha512.Oid, ml_dsa_87_with_sha512 },
        });

        private readonly string m_name;
        private readonly MLDsaParameterSet m_parameterSet;
        private readonly DerObjectIdentifier m_oid;
        private readonly DerObjectIdentifier m_preHashOid;

        private MLDsaParameters(string name, MLDsaParameterSet parameterSet, DerObjectIdentifier oid,
            DerObjectIdentifier preHashOid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_parameterSet = parameterSet ?? throw new ArgumentNullException(nameof(parameterSet));
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
            m_preHashOid = preHashOid;
        }

        public bool IsPreHash => m_preHashOid != null;

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        internal DerObjectIdentifier PreHashOid => m_preHashOid;

        public MLDsaParameterSet ParameterSet => m_parameterSet;

        public override string ToString() => Name;
    }
}
