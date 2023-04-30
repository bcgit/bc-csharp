using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal interface ISphincsPlusEngineProvider
    {
        int N { get; }

        SphincsPlusEngine Get();
    }

    public sealed class SphincsPlusParameters : ICipherParameters
    {
        public static SphincsPlusParameters sha2_128f = new SphincsPlusParameters("sha2-128f-robust",
            new Sha2EngineProvider(true, 16, 16, 22, 6, 33, 66));

        public static SphincsPlusParameters sha2_128s = new SphincsPlusParameters("sha2-128s-robust",
            new Sha2EngineProvider(true, 16, 16, 7, 12, 14, 63));

        public static SphincsPlusParameters sha2_192f = new SphincsPlusParameters("sha2-192f-robust",
            new Sha2EngineProvider(true, 24, 16, 22, 8, 33, 66));

        public static SphincsPlusParameters sha2_192s = new SphincsPlusParameters("sha2-192s-robust",
            new Sha2EngineProvider(true, 24, 16, 7, 14, 17, 63));

        public static SphincsPlusParameters sha2_256f = new SphincsPlusParameters("sha2-256f-robust",
            new Sha2EngineProvider(true, 32, 16, 17, 9, 35, 68));

        public static SphincsPlusParameters sha2_256s = new SphincsPlusParameters("sha2-256s-robust",
            new Sha2EngineProvider(true, 32, 16, 8, 14, 22, 64));

        public static SphincsPlusParameters sha2_128f_simple = new SphincsPlusParameters("sha2-128f-simple",
            new Sha2EngineProvider(false, 16, 16, 22, 6, 33, 66));

        public static SphincsPlusParameters sha2_128s_simple = new SphincsPlusParameters("sha2-128s-simple",
            new Sha2EngineProvider(false, 16, 16, 7, 12, 14, 63));

        public static SphincsPlusParameters sha2_192f_simple = new SphincsPlusParameters("sha2-192f-simple",
            new Sha2EngineProvider(false, 24, 16, 22, 8, 33, 66));

        public static SphincsPlusParameters sha2_192s_simple = new SphincsPlusParameters("sha2-192s-simple",
            new Sha2EngineProvider(false, 24, 16, 7, 14, 17, 63));

        public static SphincsPlusParameters sha2_256f_simple = new SphincsPlusParameters("sha2-256f-simple",
            new Sha2EngineProvider(false, 32, 16, 17, 9, 35, 68));

        public static SphincsPlusParameters sha2_256s_simple = new SphincsPlusParameters("sha2-256s-simple",
            new Sha2EngineProvider(false, 32, 16, 8, 14, 22, 64));

        // SHAKE-256.

        public static SphincsPlusParameters shake_128f = new SphincsPlusParameters("shake-128f-robust",
            new Shake256EngineProvider(true, 16, 16, 22, 6, 33, 66));

        public static SphincsPlusParameters shake_128s = new SphincsPlusParameters("shake-128s-robust",
            new Shake256EngineProvider(true, 16, 16, 7, 12, 14, 63));

        public static SphincsPlusParameters shake_192f = new SphincsPlusParameters("shake-192f-robust",
            new Shake256EngineProvider(true, 24, 16, 22, 8, 33, 66));

        public static SphincsPlusParameters shake_192s = new SphincsPlusParameters("shake-192s-robust",
            new Shake256EngineProvider(true, 24, 16, 7, 14, 17, 63));

        public static SphincsPlusParameters shake_256f = new SphincsPlusParameters("shake-256f-robust",
            new Shake256EngineProvider(true, 32, 16, 17, 9, 35, 68));

        public static SphincsPlusParameters shake_256s = new SphincsPlusParameters("shake-256s-robust",
            new Shake256EngineProvider(true, 32, 16, 8, 14, 22, 64));

        public static SphincsPlusParameters shake_128f_simple = new SphincsPlusParameters("shake-128f-simple",
            new Shake256EngineProvider(false, 16, 16, 22, 6, 33, 66));

        public static SphincsPlusParameters shake_128s_simple = new SphincsPlusParameters("shake-128s-simple",
            new Shake256EngineProvider(false, 16, 16, 7, 12, 14, 63));

        public static SphincsPlusParameters shake_192f_simple = new SphincsPlusParameters("shake-192f-simple",
            new Shake256EngineProvider(false, 24, 16, 22, 8, 33, 66));

        public static SphincsPlusParameters shake_192s_simple = new SphincsPlusParameters("shake-192s-simple",
            new Shake256EngineProvider(false, 24, 16, 7, 14, 17, 63));

        public static SphincsPlusParameters shake_256f_simple = new SphincsPlusParameters("shake-256f-simple",
            new Shake256EngineProvider(false, 32, 16, 17, 9, 35, 68));

        public static SphincsPlusParameters shake_256s_simple = new SphincsPlusParameters("shake-256s-simple",
            new Shake256EngineProvider(false, 32, 16, 8, 14, 22, 64));

        // Haraka.

        public static SphincsPlusParameters haraka_128f = new SphincsPlusParameters("haraka-128f-robust", new Haraka256EngineProvider(true, 16, 16, 22, 6, 33, 66));
        public static SphincsPlusParameters haraka_128s = new SphincsPlusParameters("haraka-128s-robust", new Haraka256EngineProvider(true, 16, 16, 7, 12, 14, 63));

        public static SphincsPlusParameters haraka_256f = new SphincsPlusParameters("haraka-256f-robust", new Haraka256EngineProvider(true, 32, 16, 17, 9, 35, 68));
        public static SphincsPlusParameters haraka_256s = new SphincsPlusParameters("haraka-256s-robust", new Haraka256EngineProvider(true, 32, 16, 8, 14, 22, 64));

        public static SphincsPlusParameters haraka_192f = new SphincsPlusParameters("haraka-192f-robust", new Haraka256EngineProvider(true, 24, 16, 22, 8, 33, 66));
        public static SphincsPlusParameters haraka_192s = new SphincsPlusParameters("haraka-192s-robust", new Haraka256EngineProvider(true, 24, 16, 7, 14, 17, 63));

        public static SphincsPlusParameters haraka_128f_simple = new SphincsPlusParameters("haraka-128f-simple", new Haraka256EngineProvider(false, 16, 16, 22, 6, 33, 66));
        public static SphincsPlusParameters haraka_128s_simple = new SphincsPlusParameters("haraka-128s-simple", new Haraka256EngineProvider(false, 16, 16, 7, 12, 14, 63));

        public static SphincsPlusParameters haraka_192f_simple = new SphincsPlusParameters("haraka-192f-simple", new Haraka256EngineProvider(false, 24, 16, 22, 8, 33, 66));
        public static SphincsPlusParameters haraka_192s_simple = new SphincsPlusParameters("haraka-192s-simple", new Haraka256EngineProvider(false, 24, 16, 7, 14, 17, 63));

        public static SphincsPlusParameters haraka_256f_simple = new SphincsPlusParameters("haraka-256f-simple", new Haraka256EngineProvider(false, 32, 16, 17, 9, 35, 68));
        public static SphincsPlusParameters haraka_256s_simple = new SphincsPlusParameters("haraka-256s-simple", new Haraka256EngineProvider(false, 32, 16, 8, 14, 22, 64));


        private static uint sphincsPlus_sha2_128f_robust = 0x010101;
        private static uint sphincsPlus_sha2_128s_robust = 0x010102;
        private static uint sphincsPlus_sha2_192f_robust = 0x010103;
        private static uint sphincsPlus_sha2_192s_robust = 0x010104;
        private static uint sphincsPlus_sha2_256f_robust = 0x010105;
        private static uint sphincsPlus_sha2_256s_robust = 0x010106;

        private static uint sphincsPlus_sha2_128f_simple = 0x010201;
        private static uint sphincsPlus_sha2_128s_simple = 0x010202;
        private static uint sphincsPlus_sha2_192f_simple = 0x010203;
        private static uint sphincsPlus_sha2_192s_simple = 0x010204;
        private static uint sphincsPlus_sha2_256f_simple = 0x010205;
        private static uint sphincsPlus_sha2_256s_simple = 0x010206;

        private static uint sphincsPlus_shake_128f_robust = 0x020101;
        private static uint sphincsPlus_shake_128s_robust = 0x020102;
        private static uint sphincsPlus_shake_192f_robust = 0x020103;
        private static uint sphincsPlus_shake_192s_robust = 0x020104;
        private static uint sphincsPlus_shake_256f_robust = 0x020105;
        private static uint sphincsPlus_shake_256s_robust = 0x020106;

        private static uint sphincsPlus_shake_128f_simple = 0x020201;
        private static uint sphincsPlus_shake_128s_simple = 0x020202;
        private static uint sphincsPlus_shake_192f_simple = 0x020203;
        private static uint sphincsPlus_shake_192s_simple = 0x020204;
        private static uint sphincsPlus_shake_256f_simple = 0x020205;
        private static uint sphincsPlus_shake_256s_simple = 0x020206;

        private static uint sphincsPlus_haraka_128f_robust = 0x030101;
        private static uint sphincsPlus_haraka_128s_robust = 0x030102;
        private static uint sphincsPlus_haraka_192f_robust = 0x030103;
        private static uint sphincsPlus_haraka_192s_robust = 0x030104;
        private static uint sphincsPlus_haraka_256f_robust = 0x030105;
        private static uint sphincsPlus_haraka_256s_robust = 0x030106;

        private static uint sphincsPlus_haraka_128f_simple = 0x030201;
        private static uint sphincsPlus_haraka_128s_simple = 0x030202;
        private static uint sphincsPlus_haraka_192f_simple = 0x030203;
        private static uint sphincsPlus_haraka_192s_simple = 0x030204;
        private static uint sphincsPlus_haraka_256f_simple = 0x030205;
        private static uint sphincsPlus_haraka_256s_simple = 0x030206;


        private static Dictionary<uint, SphincsPlusParameters> oidToParams = new Dictionary<uint, SphincsPlusParameters>();
        private static Dictionary<SphincsPlusParameters, uint> paramsToOid = new Dictionary<SphincsPlusParameters, uint>();

        static SphincsPlusParameters()
        {
            oidToParams[sphincsPlus_sha2_128f_robust] = SphincsPlusParameters.sha2_128f;
            oidToParams[sphincsPlus_sha2_128s_robust] = SphincsPlusParameters.sha2_128s;
            oidToParams[sphincsPlus_sha2_192f_robust] = SphincsPlusParameters.sha2_192f;
            oidToParams[sphincsPlus_sha2_192s_robust] = SphincsPlusParameters.sha2_192s;
            oidToParams[sphincsPlus_sha2_256f_robust] = SphincsPlusParameters.sha2_256f;
            oidToParams[sphincsPlus_sha2_256s_robust] = SphincsPlusParameters.sha2_256s;

            oidToParams[sphincsPlus_sha2_128f_simple] = SphincsPlusParameters.sha2_128f_simple;
            oidToParams[sphincsPlus_sha2_128s_simple] = SphincsPlusParameters.sha2_128s_simple;
            oidToParams[sphincsPlus_sha2_192f_simple] = SphincsPlusParameters.sha2_192f_simple;
            oidToParams[sphincsPlus_sha2_192s_simple] = SphincsPlusParameters.sha2_192s_simple;
            oidToParams[sphincsPlus_sha2_256f_simple] = SphincsPlusParameters.sha2_256f_simple;
            oidToParams[sphincsPlus_sha2_256s_simple] = SphincsPlusParameters.sha2_256s_simple;

            oidToParams[sphincsPlus_shake_128f_robust] = SphincsPlusParameters.shake_128f;
            oidToParams[sphincsPlus_shake_128s_robust] = SphincsPlusParameters.shake_128s;
            oidToParams[sphincsPlus_shake_192f_robust] = SphincsPlusParameters.shake_192f;
            oidToParams[sphincsPlus_shake_192s_robust] = SphincsPlusParameters.shake_192s;
            oidToParams[sphincsPlus_shake_256f_robust] = SphincsPlusParameters.shake_256f;
            oidToParams[sphincsPlus_shake_256s_robust] = SphincsPlusParameters.shake_256s;

            oidToParams[sphincsPlus_shake_128f_simple] = SphincsPlusParameters.shake_128f_simple;
            oidToParams[sphincsPlus_shake_128s_simple] = SphincsPlusParameters.shake_128s_simple;
            oidToParams[sphincsPlus_shake_192f_simple] = SphincsPlusParameters.shake_192f_simple;
            oidToParams[sphincsPlus_shake_192s_simple] = SphincsPlusParameters.shake_192s_simple;
            oidToParams[sphincsPlus_shake_256f_simple] = SphincsPlusParameters.shake_256f_simple;
            oidToParams[sphincsPlus_shake_256s_simple] = SphincsPlusParameters.shake_256s_simple;

            oidToParams[sphincsPlus_haraka_128f_simple] = SphincsPlusParameters.haraka_128f_simple;
            oidToParams[sphincsPlus_haraka_128f_robust] = SphincsPlusParameters.haraka_128f;
            oidToParams[sphincsPlus_haraka_192f_simple] = SphincsPlusParameters.haraka_192f_simple;
            oidToParams[sphincsPlus_haraka_192f_robust] = SphincsPlusParameters.haraka_192f;
            oidToParams[sphincsPlus_haraka_256f_simple] = SphincsPlusParameters.haraka_256f_simple;
            oidToParams[sphincsPlus_haraka_256f_robust] = SphincsPlusParameters.haraka_256f;

            oidToParams[sphincsPlus_haraka_128s_simple] = SphincsPlusParameters.haraka_128s_simple;
            oidToParams[sphincsPlus_haraka_128s_robust] = SphincsPlusParameters.haraka_128s;
            oidToParams[sphincsPlus_haraka_192s_simple] = SphincsPlusParameters.haraka_192s_simple;
            oidToParams[sphincsPlus_haraka_192s_robust] = SphincsPlusParameters.haraka_192s;
            oidToParams[sphincsPlus_haraka_256s_simple] = SphincsPlusParameters.haraka_256s_simple;
            oidToParams[sphincsPlus_haraka_256s_robust] = SphincsPlusParameters.haraka_256s;


            paramsToOid[SphincsPlusParameters.sha2_128f] = sphincsPlus_sha2_128f_robust;
            paramsToOid[SphincsPlusParameters.sha2_128s] = sphincsPlus_sha2_128s_robust;
            paramsToOid[SphincsPlusParameters.sha2_192f] = sphincsPlus_sha2_192f_robust;
            paramsToOid[SphincsPlusParameters.sha2_192s] = sphincsPlus_sha2_192s_robust;
            paramsToOid[SphincsPlusParameters.sha2_256f] = sphincsPlus_sha2_256f_robust;
            paramsToOid[SphincsPlusParameters.sha2_256s] = sphincsPlus_sha2_256s_robust;

            paramsToOid[SphincsPlusParameters.sha2_128f_simple] = sphincsPlus_sha2_128f_simple;
            paramsToOid[SphincsPlusParameters.sha2_128s_simple] = sphincsPlus_sha2_128s_simple;
            paramsToOid[SphincsPlusParameters.sha2_192f_simple] = sphincsPlus_sha2_192f_simple;
            paramsToOid[SphincsPlusParameters.sha2_192s_simple] = sphincsPlus_sha2_192s_simple;
            paramsToOid[SphincsPlusParameters.sha2_256f_simple] = sphincsPlus_sha2_256f_simple;
            paramsToOid[SphincsPlusParameters.sha2_256s_simple] = sphincsPlus_sha2_256s_simple;

            paramsToOid[SphincsPlusParameters.shake_128f] = sphincsPlus_shake_128f_robust;
            paramsToOid[SphincsPlusParameters.shake_128s] = sphincsPlus_shake_128s_robust;
            paramsToOid[SphincsPlusParameters.shake_192f] = sphincsPlus_shake_192f_robust;
            paramsToOid[SphincsPlusParameters.shake_192s] = sphincsPlus_shake_192s_robust;
            paramsToOid[SphincsPlusParameters.shake_256f] = sphincsPlus_shake_256f_robust;
            paramsToOid[SphincsPlusParameters.shake_256s] = sphincsPlus_shake_256s_robust;

            paramsToOid[SphincsPlusParameters.shake_128f_simple] = sphincsPlus_shake_128f_simple;
            paramsToOid[SphincsPlusParameters.shake_128s_simple] = sphincsPlus_shake_128s_simple;
            paramsToOid[SphincsPlusParameters.shake_192f_simple] = sphincsPlus_shake_192f_simple;
            paramsToOid[SphincsPlusParameters.shake_192s_simple] = sphincsPlus_shake_192s_simple;
            paramsToOid[SphincsPlusParameters.shake_256f_simple] = sphincsPlus_shake_256f_simple;
            paramsToOid[SphincsPlusParameters.shake_256s_simple] = sphincsPlus_shake_256s_simple;

            paramsToOid[SphincsPlusParameters.haraka_128f_simple] = sphincsPlus_haraka_128f_simple;
            paramsToOid[SphincsPlusParameters.haraka_192f_simple] = sphincsPlus_haraka_192f_simple;
            paramsToOid[SphincsPlusParameters.haraka_256f_simple] = sphincsPlus_haraka_256f_simple;
            paramsToOid[SphincsPlusParameters.haraka_128s_simple] = sphincsPlus_haraka_128s_simple;
            paramsToOid[SphincsPlusParameters.haraka_192s_simple] = sphincsPlus_haraka_192s_simple;
            paramsToOid[SphincsPlusParameters.haraka_256s_simple] = sphincsPlus_haraka_256s_simple;
            paramsToOid[SphincsPlusParameters.haraka_128f] = sphincsPlus_haraka_128f_robust;
            paramsToOid[SphincsPlusParameters.haraka_192f] = sphincsPlus_haraka_192f_robust;
            paramsToOid[SphincsPlusParameters.haraka_256f] = sphincsPlus_haraka_256f_robust;
            paramsToOid[SphincsPlusParameters.haraka_128s] = sphincsPlus_haraka_128s_robust;
            paramsToOid[SphincsPlusParameters.haraka_192s] = sphincsPlus_haraka_192s_robust;
            paramsToOid[SphincsPlusParameters.haraka_256s] = sphincsPlus_haraka_256s_robust;
        }

        private readonly string m_name;
        private readonly ISphincsPlusEngineProvider m_engineProvider;

        private SphincsPlusParameters(string name, ISphincsPlusEngineProvider engineProvider)
        {
            m_name = name;
            m_engineProvider = engineProvider;
        }

        public string Name => m_name;

        internal int N => m_engineProvider.N;

        internal SphincsPlusEngine GetEngine()
        {
            return m_engineProvider.Get();
        }

        /**
         * Return the SPHINCS+ parameters that map to the passed in parameter ID.
         * 
         * @param id the oid of interest.
         * @return the parameter set.
         */
        public static SphincsPlusParameters GetParams(int id)
        {
            return oidToParams[Convert.ToUInt32(id)];
        }

        /**
         * Return the OID that maps to the passed in SPHINCS+ parameters.
         *
         * @param params the parameters of interest.
         * @return the OID for the parameter set.
         */
        public static int GetID(SphincsPlusParameters parameters)
        {
            return Convert.ToInt32(paramsToOid[parameters]);
        }

        public byte[] GetEncoded()
        {
            return Pack.UInt32_To_BE((uint)GetID(this));
        }
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

        public SphincsPlusEngine Get()
        {
            return new SphincsPlusEngine.Sha2Engine(robust, n, w, d, a, k, h);
        }
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

        public SphincsPlusEngine Get()
        {
            return new SphincsPlusEngine.Shake256Engine(robust, n, w, d, a, k, h);
        }
    }

    internal sealed class Haraka256EngineProvider
        : ISphincsPlusEngineProvider
    {
        private readonly bool robust;
        private readonly int n;
        private readonly uint w;
        private readonly uint d;
        private readonly int a;
        private readonly int k;
        private readonly uint h;

        public Haraka256EngineProvider(bool robust, int n, uint w, uint d, int a, int k, uint h)
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

        public SphincsPlusEngine Get()
        {
#if NETCOREAPP3_0_OR_GREATER
            if (SphincsPlusEngine.HarakaSEngine_X86.IsSupported)
                return new SphincsPlusEngine.HarakaSEngine_X86(robust, n, w, d, a, k, h);
#endif

            return new SphincsPlusEngine.HarakaSEngine(robust, n, w, d, a, k, h);
        }
    }
}
