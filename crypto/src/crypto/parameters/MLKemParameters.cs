using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLKemParameters
    {
        public static readonly MLKemParameters ml_kem_512 = new MLKemParameters("ML-KEM-512",
            MLKemParameterSet.ml_kem_512, NistObjectIdentifiers.id_alg_ml_kem_512);
        public static readonly MLKemParameters ml_kem_768 = new MLKemParameters("ML-KEM-768",
            MLKemParameterSet.ml_kem_768, NistObjectIdentifiers.id_alg_ml_kem_768);
        public static readonly MLKemParameters ml_kem_1024 = new MLKemParameters("ML-KEM-1024",
            MLKemParameterSet.ml_kem_1024, NistObjectIdentifiers.id_alg_ml_kem_1024);

        internal static readonly IDictionary<string, MLKemParameters> ByName = CollectionUtilities.ReadOnly(
            new Dictionary<string, MLKemParameters>()
        {
            { ml_kem_512.Name, ml_kem_512 },
            { ml_kem_768.Name, ml_kem_768 },
            { ml_kem_1024.Name, ml_kem_1024 },
        });

        internal static readonly IDictionary<DerObjectIdentifier, MLKemParameters> ByOid = CollectionUtilities.ReadOnly(
            new Dictionary<DerObjectIdentifier, MLKemParameters>()
        {
            { ml_kem_512.Oid, ml_kem_512 },
            { ml_kem_768.Oid, ml_kem_768 },
            { ml_kem_1024.Oid, ml_kem_1024 },
        });

        private readonly string m_name;
        private readonly MLKemParameterSet m_parameterSet;
        private readonly DerObjectIdentifier m_oid;

        private MLKemParameters(string name, MLKemParameterSet parameterSet, DerObjectIdentifier oid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_parameterSet = parameterSet ?? throw new ArgumentNullException(nameof(parameterSet));
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
        }

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        public MLKemParameterSet ParameterSet => m_parameterSet;

        public override string ToString() => Name;
    }
}
