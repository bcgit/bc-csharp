using System;
using System.Runtime.ConstrainedExecution;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    [Obsolete("Will be removed")]
    public sealed class SikeParameters
    {
        private class SikeP434Engine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(434, false, null);
        }

        private class SikeP503Engine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(503, false, null);
        }

        private class SikeP610Engine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(610, false, null);
        }

        private class SikeP751Engine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(751, false, null);
        }

        private class SikeP434CompressedEngine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(434, true, null);
        }

        private class SikeP503CompressedEngine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(503, true, null);
        }

        private class SikeP610CompressedEngine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(610, true, null);
        }

        private class SikeP751CompressedEngine
        {
            internal static readonly SikeEngine Instance = new SikeEngine(751, true, null);
        }

        public static readonly SikeParameters sikep434 = new SikeParameters(434, false, "sikep434");
        public static readonly SikeParameters sikep503 = new SikeParameters(503, false, "sikep503");
        public static readonly SikeParameters sikep610 = new SikeParameters(610, false, "sikep610");
        public static readonly SikeParameters sikep751 = new SikeParameters(751, false, "sikep751");

        public static readonly SikeParameters sikep434_compressed = new SikeParameters(434, true, "sikep434_compressed");
        public static readonly SikeParameters sikep503_compressed = new SikeParameters(503, true, "sikep503_compressed");
        public static readonly SikeParameters sikep610_compressed = new SikeParameters(610, true, "sikep610_compressed");
        public static readonly SikeParameters sikep751_compressed = new SikeParameters(751, true, "sikep751_compressed");

        private readonly int ver;
        private readonly bool isCompressed;
        private readonly string name;

        private SikeParameters(int ver, bool isCompressed, string name)
        {
            this.ver = ver;
            this.isCompressed = isCompressed;
            this.name = name;
        }

        internal SikeEngine GetEngine()
        {
            if (isCompressed)
            {
                switch (ver)
                {
                case 434:   return SikeP434CompressedEngine.Instance;
                case 503:   return SikeP503CompressedEngine.Instance;
                case 610:   return SikeP610CompressedEngine.Instance;
                case 751:   return SikeP751CompressedEngine.Instance;
                default:    throw new InvalidOperationException();
                }
            }
            else
            {
                switch (ver)
                {
                case 434:   return SikeP434Engine.Instance;
                case 503:   return SikeP503Engine.Instance;
                case 610:   return SikeP610Engine.Instance;
                case 751:   return SikeP751Engine.Instance;
                default:    throw new InvalidOperationException();
                }
            }
        }

        public string Name => name;

        public int DefaultKeySize => (int)GetEngine().GetDefaultSessionKeySize();
    }
}
