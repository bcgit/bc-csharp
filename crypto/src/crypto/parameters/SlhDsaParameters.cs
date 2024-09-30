using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    internal interface ISphincsPlusEngineProvider
    {
        int N { get; }

        SphincsPlusEngine Get();
    }

    public sealed class SlhDsaParameters
    {
        public static readonly SlhDsaParameters SLH_DSA_SHA2_128s = new SlhDsaParameters(
            "SLH-DSA-SHA2-128s",
            new Sha2EngineProvider(false, 16, 16, 7, 12, 14, 63),
            NistObjectIdentifiers.id_slh_dsa_sha2_128s);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_128s = new SlhDsaParameters(
            "SLH-DSA-SHAKE-128s",
            new Shake256EngineProvider(false, 16, 16, 7, 12, 14, 63),
            NistObjectIdentifiers.id_slh_dsa_shake_128s);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_128f = new SlhDsaParameters(
            "SLH-DSA-SHA2-128f",
            new Sha2EngineProvider(false, 16, 16, 22, 6, 33, 66),
            NistObjectIdentifiers.id_slh_dsa_sha2_128f);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_128f = new SlhDsaParameters(
            "SLH-DSA-SHAKE-128f",
            new Shake256EngineProvider(false, 16, 16, 22, 6, 33, 66),
            NistObjectIdentifiers.id_slh_dsa_shake_128f);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_192s = new SlhDsaParameters(
            "SLH-DSA-SHA2-192s",
            new Sha2EngineProvider(false, 24, 16, 7, 14, 17, 63),
            NistObjectIdentifiers.id_slh_dsa_sha2_192s);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_192s = new SlhDsaParameters(
            "SLH-DSA-SHAKE-192s",
            new Shake256EngineProvider(false, 24, 16, 7, 14, 17, 63),
            NistObjectIdentifiers.id_slh_dsa_shake_192s);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_192f = new SlhDsaParameters(
            "SLH-DSA-SHA2-192f",
            new Sha2EngineProvider(false, 24, 16, 22, 8, 33, 66),
            NistObjectIdentifiers.id_slh_dsa_sha2_192f);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_192f = new SlhDsaParameters(
            "SLH-DSA-SHAKE-192f",
            new Shake256EngineProvider(false, 24, 16, 22, 8, 33, 66),
            NistObjectIdentifiers.id_slh_dsa_shake_192f);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_256s = new SlhDsaParameters(
            "SLH-DSA-SHA2-256s",
            new Sha2EngineProvider(false, 32, 16, 8, 14, 22, 64),
            NistObjectIdentifiers.id_slh_dsa_sha2_256s);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_256s = new SlhDsaParameters(
            "SLH-DSA-SHAKE-256s",
            new Shake256EngineProvider(false, 32, 16, 8, 14, 22, 64),
            NistObjectIdentifiers.id_slh_dsa_shake_256s);

        public static readonly SlhDsaParameters SLH_DSA_SHA2_256f = new SlhDsaParameters(
            "SLH-DSA-SHA2-256f",
            new Sha2EngineProvider(false, 32, 16, 17, 9, 35, 68),
            NistObjectIdentifiers.id_slh_dsa_sha2_256f);
        public static readonly SlhDsaParameters SLH_DSA_SHAKE_256f = new SlhDsaParameters(
            "SLH-DSA-SHAKE-256f",
            new Shake256EngineProvider(false, 32, 16, 17, 9, 35, 68),
            NistObjectIdentifiers.id_slh_dsa_shake_256f);

        private static readonly Dictionary<string, SlhDsaParameters> ByName =
            new Dictionary<string, SlhDsaParameters>()
        {
            { SlhDsaParameters.SLH_DSA_SHA2_128f.Name, SlhDsaParameters.SLH_DSA_SHA2_128f },
            { SlhDsaParameters.SLH_DSA_SHA2_128s.Name, SlhDsaParameters.SLH_DSA_SHA2_128s },
            { SlhDsaParameters.SLH_DSA_SHA2_192f.Name, SlhDsaParameters.SLH_DSA_SHA2_192f },
            { SlhDsaParameters.SLH_DSA_SHA2_192s.Name, SlhDsaParameters.SLH_DSA_SHA2_192s },
            { SlhDsaParameters.SLH_DSA_SHA2_256f.Name, SlhDsaParameters.SLH_DSA_SHA2_256f },
            { SlhDsaParameters.SLH_DSA_SHA2_256s.Name, SlhDsaParameters.SLH_DSA_SHA2_256s },
            { SlhDsaParameters.SLH_DSA_SHAKE_128f.Name, SlhDsaParameters.SLH_DSA_SHAKE_128f },
            { SlhDsaParameters.SLH_DSA_SHAKE_128s.Name, SlhDsaParameters.SLH_DSA_SHAKE_128s },
            { SlhDsaParameters.SLH_DSA_SHAKE_192f.Name, SlhDsaParameters.SLH_DSA_SHAKE_192f },
            { SlhDsaParameters.SLH_DSA_SHAKE_192s.Name, SlhDsaParameters.SLH_DSA_SHAKE_192s },
            { SlhDsaParameters.SLH_DSA_SHAKE_256f.Name, SlhDsaParameters.SLH_DSA_SHAKE_256f },
            { SlhDsaParameters.SLH_DSA_SHAKE_256s.Name, SlhDsaParameters.SLH_DSA_SHAKE_256s },
        };

        private static readonly Dictionary<DerObjectIdentifier, SlhDsaParameters> ByOid =
            new Dictionary<DerObjectIdentifier, SlhDsaParameters>()
        {
            { SlhDsaParameters.SLH_DSA_SHA2_128f.Oid, SlhDsaParameters.SLH_DSA_SHA2_128f },
            { SlhDsaParameters.SLH_DSA_SHA2_128s.Oid, SlhDsaParameters.SLH_DSA_SHA2_128s },
            { SlhDsaParameters.SLH_DSA_SHA2_192f.Oid, SlhDsaParameters.SLH_DSA_SHA2_192f },
            { SlhDsaParameters.SLH_DSA_SHA2_192s.Oid, SlhDsaParameters.SLH_DSA_SHA2_192s },
            { SlhDsaParameters.SLH_DSA_SHA2_256f.Oid, SlhDsaParameters.SLH_DSA_SHA2_256f },
            { SlhDsaParameters.SLH_DSA_SHA2_256s.Oid, SlhDsaParameters.SLH_DSA_SHA2_256s },
            { SlhDsaParameters.SLH_DSA_SHAKE_128f.Oid, SlhDsaParameters.SLH_DSA_SHAKE_128f },
            { SlhDsaParameters.SLH_DSA_SHAKE_128s.Oid, SlhDsaParameters.SLH_DSA_SHAKE_128s },
            { SlhDsaParameters.SLH_DSA_SHAKE_192f.Oid, SlhDsaParameters.SLH_DSA_SHAKE_192f },
            { SlhDsaParameters.SLH_DSA_SHAKE_192s.Oid, SlhDsaParameters.SLH_DSA_SHAKE_192s },
            { SlhDsaParameters.SLH_DSA_SHAKE_256f.Oid, SlhDsaParameters.SLH_DSA_SHAKE_256f },
            { SlhDsaParameters.SLH_DSA_SHAKE_256s.Oid, SlhDsaParameters.SLH_DSA_SHAKE_256s },
        };

        internal static SlhDsaParameters FromName(string name) => CollectionUtilities.GetValueOrNull(ByName, name);

        internal static SlhDsaParameters FromOid(DerObjectIdentifier oid) =>
            CollectionUtilities.GetValueOrNull(ByOid, oid);

        private readonly string m_name;
        private readonly ISphincsPlusEngineProvider m_engineProvider;
        private readonly DerObjectIdentifier m_oid;

        private SlhDsaParameters(string name, ISphincsPlusEngineProvider engineProvider, DerObjectIdentifier oid)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_engineProvider = engineProvider;
            m_oid = oid ?? throw new ArgumentNullException(nameof(oid));
        }

        public string Name => m_name;

        internal DerObjectIdentifier Oid => m_oid;

        internal int N => m_engineProvider.N;

        internal SphincsPlusEngine GetEngine() => m_engineProvider.Get();
    }

    internal sealed class Sha2EngineProvider
        : ISphincsPlusEngineProvider
    {
        private readonly bool robust;
        private readonly int n;
        private readonly uint w;
        private readonly uint d;
        private readonly int a;
        private readonly int k;
        private readonly uint h;

        internal Sha2EngineProvider(bool robust, int n, uint w, uint d, int a, int k, uint h)
        {
            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int N => this.n;

        public SphincsPlusEngine Get() => new SphincsPlusEngine.Sha2Engine(robust, n, w, d, a, k, h);
    }

    internal sealed class Shake256EngineProvider
        : ISphincsPlusEngineProvider
    {
        private readonly bool robust;
        private readonly int n;
        private readonly uint w;
        private readonly uint d;
        private readonly int a;
        private readonly int k;
        private readonly uint h;

        internal Shake256EngineProvider(bool robust, int n, uint w, uint d, int a, int k, uint h)
        {
            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int N => this.n;

        public SphincsPlusEngine Get() => new SphincsPlusEngine.Shake256Engine(robust, n, w, d, a, k, h);
    }
}
