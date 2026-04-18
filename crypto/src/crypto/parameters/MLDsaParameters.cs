using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Algorithm parameter set identifiers for ML-DSA (Module-Lattice-Based Digital Signature Algorithm) as
    /// specified in <a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>.
    /// </summary>
    /// <remarks>
    /// ML-DSA is the NIST-standardized post-quantum signature scheme derived from CRYSTALS-Dilithium. Each
    /// parameter set fixes lattice dimensions and security category. The <c>_with_sha512</c> variants wrap the
    /// pure scheme in the HashML-DSA pre-hash construction from FIPS 204, §5.4.
    /// </remarks>
    public sealed class MLDsaParameters
    {
        /// <summary>Pure ML-DSA-44 (NIST security category 2).</summary>
        public static readonly MLDsaParameters ml_dsa_44 = new MLDsaParameters("ML-DSA-44", MLDsaParameterSet.ml_dsa_44,
            NistObjectIdentifiers.id_ml_dsa_44, null);
        /// <summary>Pure ML-DSA-65 (NIST security category 3).</summary>
        public static readonly MLDsaParameters ml_dsa_65 = new MLDsaParameters("ML-DSA-65", MLDsaParameterSet.ml_dsa_65,
            NistObjectIdentifiers.id_ml_dsa_65, null);
        /// <summary>Pure ML-DSA-87 (NIST security category 5).</summary>
        public static readonly MLDsaParameters ml_dsa_87 = new MLDsaParameters("ML-DSA-87", MLDsaParameterSet.ml_dsa_87,
            NistObjectIdentifiers.id_ml_dsa_87, null);

        /// <summary>HashML-DSA-44 pre-hashed with SHA-512.</summary>
        public static readonly MLDsaParameters ml_dsa_44_with_sha512 = new MLDsaParameters("ML-DSA-44-WITH-SHA512",
            MLDsaParameterSet.ml_dsa_44, NistObjectIdentifiers.id_hash_ml_dsa_44_with_sha512,
            NistObjectIdentifiers.IdSha512);
        /// <summary>HashML-DSA-65 pre-hashed with SHA-512.</summary>
        public static readonly MLDsaParameters ml_dsa_65_with_sha512 = new MLDsaParameters("ML-DSA-65-WITH-SHA512",
            MLDsaParameterSet.ml_dsa_65, NistObjectIdentifiers.id_hash_ml_dsa_65_with_sha512,
            NistObjectIdentifiers.IdSha512);
        /// <summary>HashML-DSA-87 pre-hashed with SHA-512.</summary>
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

        /// <summary><c>true</c> for HashML-DSA variants (pre-hashed input); <c>false</c> for pure ML-DSA.</summary>
        public bool IsPreHash => m_preHashOid != null;

        /// <summary>The standard algorithm name (e.g. <c>ML-DSA-65</c> or <c>ML-DSA-65-WITH-SHA512</c>).</summary>
        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        internal DerObjectIdentifier PreHashOid => m_preHashOid;

        /// <summary>The underlying ML-DSA parameter set (lattice dimensions, number-theoretic constants).</summary>
        public MLDsaParameterSet ParameterSet => m_parameterSet;

        /// <summary>Returns the algorithm name (see <see cref="Name"/>).</summary>
        public override string ToString() => Name;
    }
}
