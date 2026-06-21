using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    /// <summary>
    /// Classic McEliece code-based KEM parameter sets. The <c>f</c> variants use the semi-systematic ("fast")
    /// matrix-reduction form, which speeds up key generation without changing the key format.
    /// </summary>
    public sealed class CmceParameters
        : ICipherParameters
    {
        private static readonly int[] poly3488 = new int[] {3, 1, 0};
        private static readonly int[] poly4608 = new int[] {10, 9, 6, 0};
        private static readonly int[] poly6688 = new int[] {7, 2, 1, 0};
        private static readonly int[] poly6960 = new int[] {8, 0};
        private static readonly int[] poly8192 = new int[] {7, 2, 1, 0};

        /// <summary>mceliece348864 parameter set (128-bit security).</summary>
        public static readonly CmceParameters mceliece348864r3 =
            new CmceParameters("mceliece348864", 12, 3488, 64, poly3488, false, 128);

        /// <summary>mceliece348864f parameter set (128-bit security, fast key generation).</summary>
        public static readonly CmceParameters mceliece348864fr3 =
            new CmceParameters("mceliece348864f", 12, 3488, 64, poly3488, true, 128);

        /// <summary>mceliece460896 parameter set (192-bit security).</summary>
        public static readonly CmceParameters mceliece460896r3 =
            new CmceParameters("mceliece460896", 13, 4608, 96, poly4608, false, 192);

        /// <summary>mceliece460896f parameter set (192-bit security, fast key generation).</summary>
        public static readonly CmceParameters mceliece460896fr3 =
            new CmceParameters("mceliece460896f", 13, 4608, 96, poly4608, true, 192);

        /// <summary>mceliece6688128 parameter set (256-bit security).</summary>
        public static readonly CmceParameters mceliece6688128r3 =
            new CmceParameters("mceliece6688128", 13, 6688, 128, poly6688, false, 256);

        /// <summary>mceliece6688128f parameter set (256-bit security, fast key generation).</summary>
        public static readonly CmceParameters mceliece6688128fr3 =
            new CmceParameters("mceliece6688128f", 13, 6688, 128, poly6688, true, 256);

        /// <summary>mceliece6960119 parameter set (256-bit security).</summary>
        public static readonly CmceParameters mceliece6960119r3 =
            new CmceParameters("mceliece6960119", 13, 6960, 119, poly6960, false, 256);

        /// <summary>mceliece6960119f parameter set (256-bit security, fast key generation).</summary>
        public static readonly CmceParameters mceliece6960119fr3 =
            new CmceParameters("mceliece6960119f", 13, 6960, 119, poly6960, true, 256);

        /// <summary>mceliece8192128 parameter set (256-bit security).</summary>
        public static readonly CmceParameters mceliece8192128r3 =
            new CmceParameters("mceliece8192128", 13, 8192, 128, poly8192, false, 256);

        /// <summary>mceliece8192128f parameter set (256-bit security, fast key generation).</summary>
        public static readonly CmceParameters mceliece8192128fr3 =
            new CmceParameters("mceliece8192128f", 13, 8192, 128, poly8192, true, 256);

        private readonly string name;
        private readonly int m;
        private readonly int n;
        private readonly int t;
        //private readonly int[] poly;
        private readonly bool usePivots;
        private readonly int defaultKeySize;
        private readonly ICmceEngine engine;

        private CmceParameters(string name, int m, int n, int t, int[] p, bool usePivots, int defaultKeySize)
        {
            this.name = name;
            this.m = m;
            this.n = n;
            this.t = t;
            //this.poly = p;
            this.usePivots = usePivots;
            this.defaultKeySize = defaultKeySize;

            switch (m)
            {
            case 12:
                this.engine = new CmceEngine<GF12>(m, n, t, p, usePivots, defaultKeySize);
                break;
            case 13:
                this.engine = new CmceEngine<GF13>(m, n, t, p, usePivots, defaultKeySize);
                break;
            default:
                throw new ArgumentException();
            }
        }

        /// <summary>The name of this parameter set.</summary>
        public string Name => name;

        /// <summary>The field extension degree <c>m</c> (<c>GF(2^m)</c>).</summary>
        public int M => m;

        /// <summary>The code length <c>n</c>.</summary>
        public int N => n;

        /// <summary>The number of errors / Goppa polynomial degree <c>t</c>.</summary>
        public int T => t;

        /// <summary>The semi-systematic parameter <c>mu</c> (non-zero only for the fast variants).</summary>
        public int Mu => usePivots ? 32 : 0;

        /// <summary>The semi-systematic parameter <c>nu</c> (non-zero only for the fast variants).</summary>
        public int Nu => usePivots ? 64 : 0;

        /// <summary>The default session key size, in bits.</summary>
        public int DefaultKeySize => defaultKeySize;

        internal ICmceEngine Engine => engine;
    }
}
