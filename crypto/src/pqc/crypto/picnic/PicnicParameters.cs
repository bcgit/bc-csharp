using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    /// <summary>The parameter sets of Picnic.</summary>
    public sealed class PicnicParameters
        : ICipherParameters
    {
        private class L1Constants
        {
            internal static readonly LowmcConstants Instance = new LowmcConstantsL1();
        }
        private class L3Constants
        {
            internal static readonly LowmcConstants Instance = new LowmcConstantsL3();
        }
        private class L5Constants
        {
            internal static readonly LowmcConstants Instance = new LowmcConstantsL5();
        }

        /// <summary>The <c>picnicl1fs</c> parameter set.</summary>
        public static PicnicParameters picnicl1fs = new PicnicParameters("picnicl1fs", 1);
        /// <summary>The <c>picnicl1ur</c> parameter set.</summary>
        public static PicnicParameters picnicl1ur = new PicnicParameters("picnicl1ur", 2);
        /// <summary>The <c>picnicl3fs</c> parameter set.</summary>
        public static PicnicParameters picnicl3fs = new PicnicParameters("picnicl3fs", 3);
        /// <summary>The <c>picnicl3ur</c> parameter set.</summary>
        public static PicnicParameters picnicl3ur = new PicnicParameters("picnicl3ur", 4);
        /// <summary>The <c>picnicl5fs</c> parameter set.</summary>
        public static PicnicParameters picnicl5fs = new PicnicParameters("picnicl5fs", 5);
        /// <summary>The <c>picnicl5ur</c> parameter set.</summary>
        public static PicnicParameters picnicl5ur = new PicnicParameters("picnicl5ur", 6);
        /// <summary>The <c>picnic3l1</c> parameter set.</summary>
        public static PicnicParameters picnic3l1 = new PicnicParameters("picnic3l1", 7);
        /// <summary>The <c>picnic3l3</c> parameter set.</summary>
        public static PicnicParameters picnic3l3 = new PicnicParameters("picnic3l3", 8);
        /// <summary>The <c>picnic3l5</c> parameter set.</summary>
        public static PicnicParameters picnic3l5 = new PicnicParameters("picnic3l5", 9);
        /// <summary>The <c>picnicl1full</c> parameter set.</summary>
        public static PicnicParameters picnicl1full = new PicnicParameters("picnicl1full", 10);
        /// <summary>The <c>picnicl3full</c> parameter set.</summary>
        public static PicnicParameters picnicl3full = new PicnicParameters("picnicl3full", 11);
        /// <summary>The <c>picnicl5full</c> parameter set.</summary>
        public static PicnicParameters picnicl5full = new PicnicParameters("picnicl5full", 12);

        private string name;
        private int param;

        private PicnicParameters(string name, int param)
        {
            this.name = name;
            this.param = param;
        }

        /// <summary>Gets the name.</summary>
        public string Name => name;

        internal PicnicEngine GetEngine()
        {
            switch (param)
            {
                case 1:
                case 2:
                case 7:
                case 10:
                    return new PicnicEngine(param, L1Constants.Instance);
                case 3:
                case 4:
                case 8:
                case 11:
                    return new PicnicEngine(param, L3Constants.Instance);
                case 12:
                case 5:
                case 6:
                case 9:
                    return new PicnicEngine(param, L5Constants.Instance);
                default: return null;
            }
        }
    }
}
