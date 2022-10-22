using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberParameters
        : ICipherParameters
    {
        public static SaberParameters lightsaberkem128r3 = new SaberParameters("lightsaberkem128r3", 2, 128);
        public static SaberParameters saberkem128r3 = new SaberParameters("saberkem128r3", 3, 128);
        public static SaberParameters firesaberkem128r3 = new SaberParameters("firesaberkem128r3", 4, 128);

        public static SaberParameters lightsaberkem192r3 = new SaberParameters("lightsaberkem192r3", 2, 192);
        public static SaberParameters saberkem192r3 = new SaberParameters("saberkem192r3", 3, 192);
        public static SaberParameters firesaberkem192r3 = new SaberParameters("firesaberkem192r3", 4, 192);

        public static SaberParameters lightsaberkem256r3 = new SaberParameters("lightsaberkem256r3", 2, 256);
        public static SaberParameters saberkem256r3 = new SaberParameters("saberkem256r3", 3, 256);
        public static SaberParameters firesaberkem256r3 = new SaberParameters("firesaberkem256r3", 4, 256);

        private readonly string name;
        private readonly int l;
        private readonly int defaultKeySize;
        private readonly SaberEngine engine;

        private SaberParameters(string name, int l, int defaultKeySize)
        {
            this.name = name;
            this.l = l;
            this.defaultKeySize = defaultKeySize;
            this.engine = new SaberEngine(l, defaultKeySize);
        }

        public string Name => name;

        public int L => l;

        public int DefaultKeySize => defaultKeySize;

        internal SaberEngine Engine => engine;
    }
}
