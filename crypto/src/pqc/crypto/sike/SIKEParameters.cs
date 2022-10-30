using System;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    [Obsolete("Will be removed")]
    public sealed class SikeParameters
    {
        public static readonly SikeParameters sikep434 = new SikeParameters(434, false, "sikep434");
        public static readonly SikeParameters sikep503 = new SikeParameters(503, false, "sikep503");
        public static readonly SikeParameters sikep610 = new SikeParameters(610, false, "sikep610");
        public static readonly SikeParameters sikep751 = new SikeParameters(751, false, "sikep751");

        public static readonly SikeParameters sikep434_compressed = new SikeParameters(434, true, "sikep434_compressed");
        public static readonly SikeParameters sikep503_compressed = new SikeParameters(503, true, "sikep503_compressed");
        public static readonly SikeParameters sikep610_compressed = new SikeParameters(610, true, "sikep610_compressed");
        public static readonly SikeParameters sikep751_compressed = new SikeParameters(751, true, "sikep751_compressed");

        private readonly string name;
        private readonly SikeEngine engine;

        public SikeParameters(int ver, bool isCompressed, string name)
        {
            this.name = name;
            this.engine = new SikeEngine(ver, isCompressed, null);
        }

        internal SikeEngine Engine => engine;

        public string Name => name;

        public int DefaultKeySize => (int)this.engine.GetDefaultSessionKeySize();
    }
}
