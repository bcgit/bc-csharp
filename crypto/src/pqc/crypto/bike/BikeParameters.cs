using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikeParameters
        : ICipherParameters
    {
        // 128 bits security
        public static BikeParameters bike128 = new BikeParameters("bike128", 12323, 142, 134, 256, 5, 3, 128);

        // 192 bits security
        public static BikeParameters bike192 = new BikeParameters("bike192", 24659, 206, 199, 256, 5, 3, 192);

        // 256 bits security
        public static BikeParameters bike256 = new BikeParameters("bike256", 40973, 274, 264, 256, 5, 3, 256);

        private readonly string name;
        private readonly int r;
        private readonly int w;
        private readonly int t;
        private readonly int l;
        private readonly int nbIter;
        private readonly int tau;
        private readonly int defaultKeySize;
        private readonly BikeEngine bikeEngine;

        private BikeParameters(string name, int r, int w, int t, int l, int nbIter, int tau, int defaultKeySize)
        {
            this.name = name;
            this.r = r;
            this.w = w;
            this.t = t;
            this.l = l;
            this.nbIter = nbIter;
            this.tau = tau;
            this.defaultKeySize = defaultKeySize;
            this.bikeEngine = new BikeEngine(r, w, t, l, nbIter, tau);
        }

        /// <summary>Gets the r.</summary>
        public int R => r;
        /// <summary>Gets the r byte.</summary>
        public int RByte => (r + 7) / 8;
        /// <summary>Gets the l byte.</summary>
        public int LByte => l / 8;
        /// <summary>Gets the w.</summary>
        public int W => w;
        /// <summary>Gets the t.</summary>
        public int T => t;
        /// <summary>Gets the l.</summary>
        public int L => l;
        /// <summary>Gets the nb iter.</summary>
        public int NbIter => nbIter;
        /// <summary>Gets the tau.</summary>
        public int Tau => tau;
        /// <summary>Gets the name.</summary>
        public string Name => name;
        /// <summary>Gets the default key size.</summary>
        public int DefaultKeySize => defaultKeySize;
        internal BikeEngine BikeEngine => bikeEngine;
    }
}
