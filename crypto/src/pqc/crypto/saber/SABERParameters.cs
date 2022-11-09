using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberParameters
        : ICipherParameters
    {
        public static SaberParameters lightsaberkem128r3 = new SaberParameters("lightsaberkem128r3", 2, 128, false, false);
        public static SaberParameters saberkem128r3 = new SaberParameters("saberkem128r3", 3, 128, false, false);
        public static SaberParameters firesaberkem128r3 = new SaberParameters("firesaberkem128r3", 4, 128, false, false);

        public static SaberParameters lightsaberkem192r3 = new SaberParameters("lightsaberkem192r3", 2, 192, false, false);
        public static SaberParameters saberkem192r3 = new SaberParameters("saberkem192r3", 3, 192, false, false);
        public static SaberParameters firesaberkem192r3 = new SaberParameters("firesaberkem192r3", 4, 192, false, false);

        public static SaberParameters lightsaberkem256r3 = new SaberParameters("lightsaberkem256r3", 2, 256, false, false);
        public static SaberParameters saberkem256r3 = new SaberParameters("saberkem256r3", 3, 256, false, false);
        public static SaberParameters firesaberkem256r3 = new SaberParameters("firesaberkem256r3", 4, 256, false, false);
        
        public static SaberParameters lightsaberkem90sr3 = new SaberParameters("lightsaberkem90sr3", 2, 256, true, false);
        public static SaberParameters saberkem90sr3 = new SaberParameters("saberkem90sr3", 3, 256, true, false);
        public static SaberParameters firesaberkem90sr3 = new SaberParameters("firesaberkem90sr3", 4, 256, true, false);

        public static SaberParameters ulightsaberkemr3 = new SaberParameters("ulightsaberkemr3", 2, 256, false, true);
        public static SaberParameters usaberkemr3 = new SaberParameters("usaberkemr3", 3, 256, false, true);
        public static SaberParameters ufiresaberkemr3 = new SaberParameters("ufiresaberkemr3", 4, 256, false, true);

        public static SaberParameters ulightsaberkem90sr3 = new SaberParameters("ulightsaberkem90sr3", 2, 256, true, true);
        public static SaberParameters usaberkem90sr3 = new SaberParameters("usaberkem90sr3", 3, 256, true, true);
        public static SaberParameters ufiresaberkem90sr3 = new SaberParameters("ufiresaberkem90sr3", 4, 256, true, true);


        private readonly string name;
        private readonly int l;
        private readonly int defaultKeySize;
        private readonly SaberEngine engine;

        private SaberParameters(string name, int l, int defaultKeySize, bool usingAes, bool usingEffectiveMasking)
        {
            this.name = name;
            this.l = l;
            this.defaultKeySize = defaultKeySize;
            this.engine = new SaberEngine(l, defaultKeySize, usingAes, usingEffectiveMasking);
        }

        public string Name => name;

        public int L => l;

        public int DefaultKeySize => defaultKeySize;

        internal SaberEngine Engine => engine;
    }
}
