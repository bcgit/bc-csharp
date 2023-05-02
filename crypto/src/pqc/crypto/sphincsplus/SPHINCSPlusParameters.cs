using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal interface ISphincsPlusEngineProvider
    {
        int N { get; }

        SphincsPlusEngine Get();
    }

    public sealed class SphincsPlusParameters
    {
        // SHA-2

        public static readonly SphincsPlusParameters sha2_128f = new SphincsPlusParameters(
            0x010101, "sha2-128f-robust", new Sha2EngineProvider(true, 16, 16, 22, 6, 33, 66));
        public static readonly SphincsPlusParameters sha2_128s = new SphincsPlusParameters(
            0x010102, "sha2-128s-robust", new Sha2EngineProvider(true, 16, 16, 7, 12, 14, 63));

        public static readonly SphincsPlusParameters sha2_192f = new SphincsPlusParameters(
            0x010103, "sha2-192f-robust", new Sha2EngineProvider(true, 24, 16, 22, 8, 33, 66));
        public static readonly SphincsPlusParameters sha2_192s = new SphincsPlusParameters(
            0x010104, "sha2-192s-robust", new Sha2EngineProvider(true, 24, 16, 7, 14, 17, 63));

        public static readonly SphincsPlusParameters sha2_256f = new SphincsPlusParameters(
            0x010105, "sha2-256f-robust", new Sha2EngineProvider(true, 32, 16, 17, 9, 35, 68));
        public static readonly SphincsPlusParameters sha2_256s = new SphincsPlusParameters(
            0x010106, "sha2-256s-robust", new Sha2EngineProvider(true, 32, 16, 8, 14, 22, 64));

        public static readonly SphincsPlusParameters sha2_128f_simple = new SphincsPlusParameters(
            0x010201, "sha2-128f-simple", new Sha2EngineProvider(false, 16, 16, 22, 6, 33, 66));
        public static readonly SphincsPlusParameters sha2_128s_simple = new SphincsPlusParameters(
            0x010202, "sha2-128s-simple", new Sha2EngineProvider(false, 16, 16, 7, 12, 14, 63));

        public static readonly SphincsPlusParameters sha2_192f_simple = new SphincsPlusParameters(
            0x010203, "sha2-192f-simple", new Sha2EngineProvider(false, 24, 16, 22, 8, 33, 66));
        public static readonly SphincsPlusParameters sha2_192s_simple = new SphincsPlusParameters(
            0x010204, "sha2-192s-simple", new Sha2EngineProvider(false, 24, 16, 7, 14, 17, 63));

        public static readonly SphincsPlusParameters sha2_256f_simple = new SphincsPlusParameters(
            0x010205, "sha2-256f-simple", new Sha2EngineProvider(false, 32, 16, 17, 9, 35, 68));
        public static readonly SphincsPlusParameters sha2_256s_simple = new SphincsPlusParameters(
            0x010206, "sha2-256s-simple", new Sha2EngineProvider(false, 32, 16, 8, 14, 22, 64));

        // SHAKE-256.

        public static readonly SphincsPlusParameters shake_128f = new SphincsPlusParameters(
            0x020101, "shake-128f-robust", new Shake256EngineProvider(true, 16, 16, 22, 6, 33, 66));
        public static readonly SphincsPlusParameters shake_128s = new SphincsPlusParameters(
            0x020102, "shake-128s-robust", new Shake256EngineProvider(true, 16, 16, 7, 12, 14, 63));

        public static readonly SphincsPlusParameters shake_192f = new SphincsPlusParameters(
            0x020103, "shake-192f-robust", new Shake256EngineProvider(true, 24, 16, 22, 8, 33, 66));
        public static readonly SphincsPlusParameters shake_192s = new SphincsPlusParameters(
            0x020104, "shake-192s-robust", new Shake256EngineProvider(true, 24, 16, 7, 14, 17, 63));

        public static readonly SphincsPlusParameters shake_256f = new SphincsPlusParameters(
            0x020105, "shake-256f-robust", new Shake256EngineProvider(true, 32, 16, 17, 9, 35, 68));
        public static readonly SphincsPlusParameters shake_256s = new SphincsPlusParameters(
            0x020106, "shake-256s-robust", new Shake256EngineProvider(true, 32, 16, 8, 14, 22, 64));

        public static readonly SphincsPlusParameters shake_128f_simple = new SphincsPlusParameters(
            0x020201, "shake-128f-simple", new Shake256EngineProvider(false, 16, 16, 22, 6, 33, 66));
        public static readonly SphincsPlusParameters shake_128s_simple = new SphincsPlusParameters(
            0x020202, "shake-128s-simple", new Shake256EngineProvider(false, 16, 16, 7, 12, 14, 63));

        public static readonly SphincsPlusParameters shake_192f_simple = new SphincsPlusParameters(
            0x020203, "shake-192f-simple", new Shake256EngineProvider(false, 24, 16, 22, 8, 33, 66));
        public static readonly SphincsPlusParameters shake_192s_simple = new SphincsPlusParameters(
            0x020204, "shake-192s-simple", new Shake256EngineProvider(false, 24, 16, 7, 14, 17, 63));

        public static readonly SphincsPlusParameters shake_256f_simple = new SphincsPlusParameters(
            0x020205, "shake-256f-simple", new Shake256EngineProvider(false, 32, 16, 17, 9, 35, 68));
        public static readonly SphincsPlusParameters shake_256s_simple = new SphincsPlusParameters(
            0x020206, "shake-256s-simple", new Shake256EngineProvider(false, 32, 16, 8, 14, 22, 64));

        // Haraka.

        public static readonly SphincsPlusParameters haraka_128f = new SphincsPlusParameters(
            0x030101, "haraka-128f-robust", new HarakaSEngineProvider(true, 16, 16, 22, 6, 33, 66));
        public static readonly SphincsPlusParameters haraka_128s = new SphincsPlusParameters(
            0x030102, "haraka-128s-robust", new HarakaSEngineProvider(true, 16, 16, 7, 12, 14, 63));

        public static readonly SphincsPlusParameters haraka_192f = new SphincsPlusParameters(
            0x030103, "haraka-192f-robust", new HarakaSEngineProvider(true, 24, 16, 22, 8, 33, 66));
        public static readonly SphincsPlusParameters haraka_192s = new SphincsPlusParameters(
            0x030104, "haraka-192s-robust", new HarakaSEngineProvider(true, 24, 16, 7, 14, 17, 63));

        public static readonly SphincsPlusParameters haraka_256f = new SphincsPlusParameters(
            0x030105, "haraka-256f-robust", new HarakaSEngineProvider(true, 32, 16, 17, 9, 35, 68));
        public static readonly SphincsPlusParameters haraka_256s = new SphincsPlusParameters(
            0x030106, "haraka-256s-robust", new HarakaSEngineProvider(true, 32, 16, 8, 14, 22, 64));

        public static readonly SphincsPlusParameters haraka_128f_simple = new SphincsPlusParameters(
            0x030201, "haraka-128f-simple", new HarakaSEngineProvider(false, 16, 16, 22, 6, 33, 66));
        public static readonly SphincsPlusParameters haraka_128s_simple = new SphincsPlusParameters(
            0x030202, "haraka-128s-simple", new HarakaSEngineProvider(false, 16, 16, 7, 12, 14, 63));

        public static readonly SphincsPlusParameters haraka_192f_simple = new SphincsPlusParameters(
            0x030203, "haraka-192f-simple", new HarakaSEngineProvider(false, 24, 16, 22, 8, 33, 66));
        public static readonly SphincsPlusParameters haraka_192s_simple = new SphincsPlusParameters(
            0x030204, "haraka-192s-simple", new HarakaSEngineProvider(false, 24, 16, 7, 14, 17, 63));

        public static readonly SphincsPlusParameters haraka_256f_simple = new SphincsPlusParameters(
            0x030205, "haraka-256f-simple", new HarakaSEngineProvider(false, 32, 16, 17, 9, 35, 68));
        public static readonly SphincsPlusParameters haraka_256s_simple = new SphincsPlusParameters(
            0x030206, "haraka-256s-simple", new HarakaSEngineProvider(false, 32, 16, 8, 14, 22, 64));

        private static readonly Dictionary<int, SphincsPlusParameters> IdToParams =
            new Dictionary<int, SphincsPlusParameters>();

        static SphincsPlusParameters()
        {
            SphincsPlusParameters[] all = new SphincsPlusParameters[]{
                SphincsPlusParameters.sha2_128f, SphincsPlusParameters.sha2_128s,
                SphincsPlusParameters.sha2_192f, SphincsPlusParameters.sha2_192s,
                SphincsPlusParameters.sha2_256f, SphincsPlusParameters.sha2_256s,
                SphincsPlusParameters.sha2_128f_simple, SphincsPlusParameters.sha2_128s_simple,
                SphincsPlusParameters.sha2_192f_simple, SphincsPlusParameters.sha2_192s_simple,
                SphincsPlusParameters.sha2_256f_simple, SphincsPlusParameters.sha2_256s_simple,
                SphincsPlusParameters.shake_128f, SphincsPlusParameters.shake_128s,
                SphincsPlusParameters.shake_192f, SphincsPlusParameters.shake_192s,
                SphincsPlusParameters.shake_256f, SphincsPlusParameters.shake_256s,
                SphincsPlusParameters.shake_128f_simple, SphincsPlusParameters.shake_128s_simple,
                SphincsPlusParameters.shake_192f_simple, SphincsPlusParameters.shake_192s_simple,
                SphincsPlusParameters.shake_256f_simple, SphincsPlusParameters.shake_256s_simple,
                SphincsPlusParameters.haraka_128f, SphincsPlusParameters.haraka_128s,
                SphincsPlusParameters.haraka_192f, SphincsPlusParameters.haraka_192s,
                SphincsPlusParameters.haraka_256f, SphincsPlusParameters.haraka_256s,
                SphincsPlusParameters.haraka_128f_simple, SphincsPlusParameters.haraka_128s_simple,
                SphincsPlusParameters.haraka_192f_simple, SphincsPlusParameters.haraka_192s_simple,
                SphincsPlusParameters.haraka_256f_simple, SphincsPlusParameters.haraka_256s_simple,
            };

            for (int i = 0; i < all.Length; ++i)
            {
                SphincsPlusParameters parameters = all[i];
                IdToParams.Add(parameters.ID, parameters);
            }
        }

        private readonly int m_id;
        private readonly string m_name;
        private readonly ISphincsPlusEngineProvider m_engineProvider;

        private SphincsPlusParameters(int id, string name, ISphincsPlusEngineProvider engineProvider)
        {
            m_id = id;
            m_name = name;
            m_engineProvider = engineProvider;
        }

        public int ID => m_id;

        public string Name => m_name;

        internal int N => m_engineProvider.N;

        internal SphincsPlusEngine GetEngine() => m_engineProvider.Get();

        /**
         * Return the SPHINCS+ parameters that map to the passed in parameter ID.
         * 
         * @param id the oid of interest.
         * @return the parameter set.
         */
        public static SphincsPlusParameters GetParams(int id) => CollectionUtilities.GetValueOrNull(IdToParams, id);

        /**
         * Return the OID that maps to the passed in SPHINCS+ parameters.
         *
         * @param params the parameters of interest.
         * @return the OID for the parameter set.
         */
        [Obsolete("Use 'ID' property instead")]
        public static int GetID(SphincsPlusParameters parameters) => parameters.ID;

        public byte[] GetEncoded() => Pack.UInt32_To_BE((uint)ID);
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

    internal sealed class HarakaSEngineProvider
        : ISphincsPlusEngineProvider
    {
        private readonly bool robust;
        private readonly int n;
        private readonly uint w;
        private readonly uint d;
        private readonly int a;
        private readonly int k;
        private readonly uint h;

        public HarakaSEngineProvider(bool robust, int n, uint w, uint d, int a, int k, uint h)
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
