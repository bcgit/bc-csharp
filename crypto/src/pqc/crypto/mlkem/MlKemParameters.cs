using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemParameters
        : IKemParameters
    {
        public static readonly MLKemParameters ml_kem_512 = new MLKemParameters("ML-KEM-512", 2,
            NistObjectIdentifiers.id_alg_ml_kem_512);
        public static readonly MLKemParameters ml_kem_768 = new MLKemParameters("ML-KEM-768", 3,
            NistObjectIdentifiers.id_alg_ml_kem_768);
        public static readonly MLKemParameters ml_kem_1024 = new MLKemParameters("ML-KEM-1024", 4,
            NistObjectIdentifiers.id_alg_ml_kem_1024);

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
        private readonly int m_k;
        private readonly DerObjectIdentifier m_oid;

        private MLKemParameters(string name, int k, DerObjectIdentifier oid)
        {
            m_name = name;
            m_k = k;
            m_oid = oid;
        }

        internal int K => m_k;

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        public int SessionKeySize => 256;

        public override string ToString() => Name;

        internal MLKemEngine GetEngine() => new MLKemEngine(m_k);
    }
}
