using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Signers.MLDsa;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// The three ML-DSA parameter sets defined by FIPS 204, identified by the matrix dimensions
    /// <c>(k, ℓ)</c> embedded in the name. Each entry binds the textual name to the engine mode that
    /// produces the standardised public-key, private-key and signature sizes.
    /// </summary>
    public sealed class MLDsaParameterSet
    {
        /// <summary>ML-DSA-44 (NIST Category 2, mode 2).</summary>
        public static readonly MLDsaParameterSet ml_dsa_44 = new MLDsaParameterSet("ML-DSA-44", 2);
        /// <summary>ML-DSA-65 (NIST Category 3, mode 3).</summary>
        public static readonly MLDsaParameterSet ml_dsa_65 = new MLDsaParameterSet("ML-DSA-65", 3);
        /// <summary>ML-DSA-87 (NIST Category 5, mode 5).</summary>
        public static readonly MLDsaParameterSet ml_dsa_87 = new MLDsaParameterSet("ML-DSA-87", 5);

        private static readonly Dictionary<string, MLDsaParameterSet> ByName =
            new Dictionary<string, MLDsaParameterSet>()
        {
            { ml_dsa_44.Name, ml_dsa_44 },
            { ml_dsa_65.Name, ml_dsa_65 },
            { ml_dsa_87.Name, ml_dsa_87 },
        };

        internal static MLDsaParameterSet FromName(string name) => CollectionUtilities.GetValueOrNull(ByName, name);

        private readonly string m_name;
        private readonly int m_mode;

        private MLDsaParameterSet(string name, int mode)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_mode = mode;
        }

        internal MLDsaEngine GetEngine(SecureRandom random) => new MLDsaEngine(m_mode, random);

        /// <summary>The textual name of this parameter set (e.g. <c>"ML-DSA-44"</c>).</summary>
        public string Name => m_name;

        internal int PrivateKeyLength
        {
            get
            {
                switch (m_mode)
                {
                case 2: return 2560;
                case 3: return 4032;
                case 5: return 4896;
                default:
                    throw new InvalidOperationException();
                }
            }
        }

        internal int PublicKeyLength
        {
            get
            {
                switch (m_mode)
                {
                case 2: return 1312;
                case 3: return 1952;
                case 5: return 2592;
                default:
                    throw new InvalidOperationException();
                }
            }
        }

        internal int SeedLength => MLDsaEngine.SeedBytes;

        /// <inheritdoc/>
        public override string ToString() => Name;
    }
}
