using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Algorithm parameter set identifiers for ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) as
    /// specified in <a href="https://csrc.nist.gov/pubs/fips/203/final">FIPS 203</a>.
    /// </summary>
    /// <remarks>
    /// ML-KEM is a post-quantum key-encapsulation mechanism standardized by NIST, derived from CRYSTALS-Kyber.
    /// Each instance binds a human-readable algorithm name, an internal <see cref="MLKemParameterSet"/>, and the
    /// NIST-assigned algorithm OID used in X.509/PKIX encodings.
    /// </remarks>
    public sealed class MLKemParameters
    {
        /// <summary>ML-KEM-512 parameter set (NIST security category 1).</summary>
        public static readonly MLKemParameters ml_kem_512 = new MLKemParameters("ML-KEM-512",
            MLKemParameterSet.ml_kem_512, NistObjectIdentifiers.id_alg_ml_kem_512);
        /// <summary>ML-KEM-768 parameter set (NIST security category 3).</summary>
        public static readonly MLKemParameters ml_kem_768 = new MLKemParameters("ML-KEM-768",
            MLKemParameterSet.ml_kem_768, NistObjectIdentifiers.id_alg_ml_kem_768);
        /// <summary>ML-KEM-1024 parameter set (NIST security category 5).</summary>
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

        /// <summary>The standard algorithm name identifying this parameter set (e.g. <c>ML-KEM-768</c>).</summary>
        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        /// <summary>The underlying ML-KEM parameter set (lattice dimensions, noise bounds, etc.).</summary>
        public MLKemParameterSet ParameterSet => m_parameterSet;

        /// <summary>Returns the algorithm name (see <see cref="Name"/>).</summary>
        public override string ToString() => Name;
    }
}
