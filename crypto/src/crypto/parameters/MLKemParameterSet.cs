using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// The three ML-KEM parameter sets defined by FIPS 203, distinguished by the module-lattice rank
    /// <c>k</c>. Each entry binds the textual name to a configured engine that produces the standardised
    /// ciphertext and shared-secret sizes.
    /// </summary>
    public sealed class MLKemParameterSet
    {
        /// <summary>ML-KEM-512 (NIST Category 1, <c>k = 2</c>).</summary>
        public static readonly MLKemParameterSet ml_kem_512 = new MLKemParameterSet("ML-KEM-512", 2);
        /// <summary>ML-KEM-768 (NIST Category 3, <c>k = 3</c>).</summary>
        public static readonly MLKemParameterSet ml_kem_768 = new MLKemParameterSet("ML-KEM-768", 3);
        /// <summary>ML-KEM-1024 (NIST Category 5, <c>k = 4</c>).</summary>
        public static readonly MLKemParameterSet ml_kem_1024 = new MLKemParameterSet("ML-KEM-1024", 4);

        private static readonly Dictionary<string, MLKemParameterSet> ByName =
            new Dictionary<string, MLKemParameterSet>()
        {
            { ml_kem_512.Name, ml_kem_512 },
            { ml_kem_768.Name, ml_kem_768 },
            { ml_kem_1024.Name, ml_kem_1024 },
        };

        internal static MLKemParameterSet FromName(string name) => CollectionUtilities.GetValueOrNull(ByName, name);

        private readonly string m_name;
        private readonly MLKemEngine m_engine;

        private MLKemParameterSet(string name, int k)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_engine = new MLKemEngine(k);
        }

        /// <summary>Length in bytes of an ML-KEM encapsulation (ciphertext) for this parameter set.</summary>
        public int EncapsulationLength => m_engine.CipherTextBytes;

        internal MLKemEngine Engine => m_engine;

        /// <summary>Length in bytes of the shared secret produced by encapsulation/decapsulation (32).</summary>
        public int SecretLength => MLKemEngine.SharedSecretBytes;

        /// <summary>The textual name of this parameter set (e.g. <c>"ML-KEM-512"</c>).</summary>
        public string Name => m_name;

        /// <inheritdoc/>
        public override string ToString() => Name;
    }
}
