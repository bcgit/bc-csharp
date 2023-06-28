using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Frodo
{
    public sealed class FrodoParameters
        : ICipherParameters
    {
        private static readonly short[] cdf_table640  = {4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767};
        private static readonly short[] cdf_table976  = {5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
        private static readonly short[] cdf_table1344 = {9142, 23462, 30338, 32361, 32725, 32765, 32767};

        public static readonly FrodoParameters frodokem640aes = new FrodoParameters("frodokem19888", 640, 15, 2, cdf_table640, new ShakeDigest(128), new FrodoMatrixGenerator.Aes128MatrixGenerator(640, (1 << 15)));
        public static readonly FrodoParameters frodokem640shake = new FrodoParameters("frodokem19888shake", 640, 15, 2, cdf_table640, new ShakeDigest(128), new FrodoMatrixGenerator.Shake128MatrixGenerator(640, (1 << 15)));

        public static readonly FrodoParameters frodokem976aes = new FrodoParameters("frodokem31296", 976, 16, 3, cdf_table976, new ShakeDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(976, (1 << 16)));
        public static readonly FrodoParameters frodokem976shake = new FrodoParameters("frodokem31296shake", 976, 16, 3, cdf_table976, new ShakeDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(976, (1 << 16)));

        public static readonly FrodoParameters frodokem1344aes = new FrodoParameters("frodokem43088", 1344, 16, 4, cdf_table1344, new ShakeDigest(256), new FrodoMatrixGenerator.Aes128MatrixGenerator(1344, (1 << 16)));
        public static readonly FrodoParameters frodokem1344shake = new FrodoParameters("frodokem43088shake", 1344, 16, 4, cdf_table1344, new ShakeDigest(256), new FrodoMatrixGenerator.Shake128MatrixGenerator(1344, (1 << 16)));

        [Obsolete("Use 'frodokem640aes' instead")]
        public static FrodoParameters frodokem19888r3 = frodokem640aes;
        [Obsolete("Use 'frodokem640shake' instead")]
        public static FrodoParameters frodokem19888shaker3 = frodokem640shake;

        [Obsolete("Use 'frodokem976aes' instead")]
        public static FrodoParameters frodokem31296r3 = frodokem976aes;
        [Obsolete("Use 'frodokem976shake' instead")]
        public static FrodoParameters frodokem31296shaker3 = frodokem976shake;

        [Obsolete("Use 'frodokem1344aes' instead")]
        public static FrodoParameters frodokem43088r3 = frodokem1344aes;
        [Obsolete("Use 'frodokem1344shake' instead")]
        public static FrodoParameters frodokem43088shaker3 = frodokem1344shake;

        private readonly string name;
        private readonly int n;
        private readonly int d;
        private readonly int b;
        private readonly short[] cdf_table;
        private readonly ShakeDigest digest;
        private readonly FrodoMatrixGenerator mGen;
        private readonly int defaultKeySize;
        private readonly FrodoEngine engine;

        private FrodoParameters(string name, int n, int d, int b, short[] cdf_table, ShakeDigest digest,
            FrodoMatrixGenerator mGen)
        {
            this.name = name;
            this.n = n;
            this.d = d;
            this.b = b;
            this.cdf_table = cdf_table;
            this.digest = digest;
            this.mGen = mGen;
            this.defaultKeySize = b * FrodoEngine.nbar * FrodoEngine.nbar;
            this.engine = new FrodoEngine(n, d, b, cdf_table, digest, mGen);
        }

        public string Name => name;

        public int DefaultKeySize => defaultKeySize;

        [Obsolete("Will be removed")]
        public FrodoEngine Engine => engine;

        [Obsolete("Will be removed")]
        public int N => n;

        [Obsolete("Will be removed")]
        public int D => d;

        [Obsolete("Will be removed")]
        public int B => b;

        [Obsolete("Will be removed")]
        public short[] CdfTable => Arrays.Clone(cdf_table);

        [Obsolete("Will be removed")]
        public IDigest Digest => new ShakeDigest(digest);

        [Obsolete("Will be removed")]
        public FrodoMatrixGenerator MGen => mGen;
    }
} 
