using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaParameters
    {
        public static readonly MLDsaParameters ml_dsa_44 = new MLDsaParameters("ml-dsa-44", MLDsaParameterSet.ML_DSA_44,
            NistObjectIdentifiers.id_ml_dsa_44);
        public static readonly MLDsaParameters ml_dsa_65 = new MLDsaParameters("ml-dsa-65", MLDsaParameterSet.ML_DSA_65,
            NistObjectIdentifiers.id_ml_dsa_65);
        public static readonly MLDsaParameters ml_dsa_87 = new MLDsaParameters("ml-dsa-87", MLDsaParameterSet.ML_DSA_87,
            NistObjectIdentifiers.id_ml_dsa_87);

        internal static readonly IDictionary<string, MLDsaParameters> ByName = CollectionUtilities.ReadOnly(
            new Dictionary<string, MLDsaParameters>()
        {
            { ml_dsa_44.Name, ml_dsa_44 },
            { ml_dsa_65.Name, ml_dsa_65 },
            { ml_dsa_87.Name, ml_dsa_87 },
        });

        internal static readonly IDictionary<DerObjectIdentifier, MLDsaParameters> ByOid = CollectionUtilities.ReadOnly(
            new Dictionary<DerObjectIdentifier, MLDsaParameters>()
        {
            { ml_dsa_44.Oid, ml_dsa_44 },
            { ml_dsa_65.Oid, ml_dsa_65 },
            { ml_dsa_87.Oid, ml_dsa_87 },
        });

        private readonly string m_name;
        private readonly MLDsaParameterSet m_parameterSet;
        private readonly DerObjectIdentifier m_oid;

        private MLDsaParameters(string name, MLDsaParameterSet parameterSet, DerObjectIdentifier oid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_parameterSet = parameterSet ?? throw new ArgumentNullException(nameof(parameterSet));
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
        }

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        internal DerObjectIdentifier PreHashOid => null;

        public MLDsaParameterSet ParameterSet => m_parameterSet;

        public override string ToString() => Name;
    }
}
