using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Kems.MLKem;
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
        private readonly MLKemEngine m_engine;

        private MLKemParameterSet(string name, int k)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_engine = new MLKemEngine(k);
        }

        public int EncapsulationLength => m_engine.CipherTextBytes;

        internal MLKemEngine Engine => m_engine;

        public int SecretLength => MLKemEngine.SharedSecretBytes;

        public string Name => m_name;

        public override string ToString() => Name;
    }
}
