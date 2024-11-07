using System;
using System.Collections.Generic;

using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Parameters
{
    internal interface ISphincsPlusEngineProvider
    {
        int N { get; }

        SphincsPlusEngine Get();
    }

    public sealed class SlhDsaParameterSet
    {
        public static readonly SlhDsaParameterSet slh_dsa_sha2_128s = new SlhDsaParameterSet("SLH-DSA-SHA2-128s",
            new Sha2EngineProvider(n: 16, w: 16, d: 7, a: 12, k: 14, h: 63));
        public static readonly SlhDsaParameterSet slh_dsa_shake_128s = new SlhDsaParameterSet("SLH-DSA-SHAKE-128s",
            new Shake256EngineProvider(n: 16, w: 16, d: 7, a: 12, k: 14, h: 63));

        public static readonly SlhDsaParameterSet slh_dsa_sha2_128f = new SlhDsaParameterSet("SLH-DSA-SHA2-128f",
            new Sha2EngineProvider(n: 16, w: 16, d: 22, a: 6, k: 33, h: 66));
        public static readonly SlhDsaParameterSet slh_dsa_shake_128f = new SlhDsaParameterSet("SLH-DSA-SHAKE-128f",
            new Shake256EngineProvider(n: 16, w: 16, d: 22, a: 6, k: 33, h: 66));

        public static readonly SlhDsaParameterSet slh_dsa_sha2_192s = new SlhDsaParameterSet("SLH-DSA-SHA2-192s",
            new Sha2EngineProvider(n: 24, w: 16, d: 7, a: 14, k: 17, h: 63));
        public static readonly SlhDsaParameterSet slh_dsa_shake_192s = new SlhDsaParameterSet("SLH-DSA-SHAKE-192s",
            new Shake256EngineProvider(n: 24, w: 16, d: 7, a: 14, k: 17, h: 63));

        public static readonly SlhDsaParameterSet slh_dsa_sha2_192f = new SlhDsaParameterSet("SLH-DSA-SHA2-192f",
            new Sha2EngineProvider(n: 24, w: 16, d: 22, a: 8, k: 33, h: 66));
        public static readonly SlhDsaParameterSet slh_dsa_shake_192f = new SlhDsaParameterSet("SLH-DSA-SHAKE-192f",
            new Shake256EngineProvider(n: 24, w: 16, d: 22, a: 8, k: 33, h: 66));

        public static readonly SlhDsaParameterSet slh_dsa_sha2_256s = new SlhDsaParameterSet("SLH-DSA-SHA2-256s",
            new Sha2EngineProvider(n: 32, w: 16, d: 8, a: 14, k: 22, h: 64));
        public static readonly SlhDsaParameterSet slh_dsa_shake_256s = new SlhDsaParameterSet("SLH-DSA-SHAKE-256s",
            new Shake256EngineProvider(n: 32, w: 16, d: 8, a: 14, k: 22, h: 64));

        public static readonly SlhDsaParameterSet slh_dsa_sha2_256f = new SlhDsaParameterSet("SLH-DSA-SHA2-256f",
            new Sha2EngineProvider(n: 32, w: 16, d: 17, a: 9, k: 35, h: 68));
        public static readonly SlhDsaParameterSet slh_dsa_shake_256f = new SlhDsaParameterSet("SLH-DSA-SHAKE-256f",
            new Shake256EngineProvider(n: 32, w: 16, d: 17, a: 9, k: 35, h: 68));

        private static readonly Dictionary<string, SlhDsaParameterSet> ByName =
            new Dictionary<string, SlhDsaParameterSet>()
        {
            { slh_dsa_sha2_128f.Name, slh_dsa_sha2_128f },
            { slh_dsa_sha2_128s.Name, slh_dsa_sha2_128s },
            { slh_dsa_sha2_192f.Name, slh_dsa_sha2_192f },
            { slh_dsa_sha2_192s.Name, slh_dsa_sha2_192s },
            { slh_dsa_sha2_256f.Name, slh_dsa_sha2_256f },
            { slh_dsa_sha2_256s.Name, slh_dsa_sha2_256s },
            { slh_dsa_shake_128f.Name, slh_dsa_shake_128f },
            { slh_dsa_shake_128s.Name, slh_dsa_shake_128s },
            { slh_dsa_shake_192f.Name, slh_dsa_shake_192f },
            { slh_dsa_shake_192s.Name, slh_dsa_shake_192s },
            { slh_dsa_shake_256f.Name, slh_dsa_shake_256f },
            { slh_dsa_shake_256s.Name, slh_dsa_shake_256s },
        };

        internal static SlhDsaParameterSet FromName(string name) => CollectionUtilities.GetValueOrNull(ByName, name);

        private readonly string m_name;
        private readonly ISphincsPlusEngineProvider m_engineProvider;

        private SlhDsaParameterSet(string name, ISphincsPlusEngineProvider engineProvider)
        {
            m_name = name ?? throw new ArgumentNullException(nameof(name));
            m_engineProvider = engineProvider;
        }

        public string Name => m_name;

        public override string ToString() => Name;

        internal int N => m_engineProvider.N;

        internal SphincsPlusEngine GetEngine() => m_engineProvider.Get();
    }

    internal sealed class Sha2EngineProvider
        : ISphincsPlusEngineProvider
    {
        private readonly int n;
        private readonly uint w;
        private readonly uint d;
        private readonly int a;
        private readonly int k;
        private readonly uint h;

        internal Sha2EngineProvider(int n, uint w, uint d, int a, int k, uint h)
        {
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int N => this.n;

        public SphincsPlusEngine Get() => new SphincsPlusEngine.Sha2Engine(robust: false, n, w, d, a, k, h);
    }

    internal sealed class Shake256EngineProvider
        : ISphincsPlusEngineProvider
    {
        private readonly int n;
        private readonly uint w;
        private readonly uint d;
        private readonly int a;
        private readonly int k;
        private readonly uint h;

        internal Shake256EngineProvider(int n, uint w, uint d, int a, int k, uint h)
        {
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int N => this.n;

        public SphincsPlusEngine Get() => new SphincsPlusEngine.Shake256Engine(robust: false, n, w, d, a, k, h);
    }
}
