using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLKemParameterSet
    {
        public static readonly MLKemParameterSet ml_kem_512 = new MLKemParameterSet("ML-KEM-512", 2);
        public static readonly MLKemParameterSet ml_kem_768 = new MLKemParameterSet("ML-KEM-768", 3);
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
        private readonly int m_k;

        private MLKemParameterSet(string name, int k)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_k = k;
        }

        internal MLKemEngine GetEngine(SecureRandom random) => new MLKemEngine(m_k, random);

        internal int K => m_k;

        public string Name => m_name;

        internal int PrivateKeyLength
        {
            get
            {
                switch (m_k)
                {
                case 2: return 1632;
                case 3: return 2400;
                case 4: return 3168;
                default:
                    throw new InvalidOperationException();
                };
            }
        }

        internal int PublicKeyLength
        {
            get
            {
                switch (m_k)
                {
                case 2: return 800;
                case 3: return 1184;
                case 4: return 1568;
                default:
                    throw new InvalidOperationException();
                };
            }
        }

        internal int SeedLength => MLKemEngine.SymBytes * 2;

        public override string ToString() => Name;
    }
}
