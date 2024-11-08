using Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /// <summary>
    /// NTRU cipher parameter sets
    /// </summary>
    public sealed class NtruParameters
        : IKemParameters
    {
        /// <summary>
        /// NTRU-HPS parameter set with n = 509 and q = 2048.
        /// </summary>
        public static readonly NtruParameters NtruHps2048509 =
            new NtruParameters("ntruhps2048509", new NtruHps2048509());

        /// <summary>
        /// NTRU-HPS parameter set with n = 677 and q = 2048.
        /// </summary>
        public static readonly NtruParameters NtruHps2048677 =
            new NtruParameters("ntruhps2048677", new NtruHps2048677());

        /// <summary>
        /// NTRU-HPS parameter set with n = 821 and q = 4096.
        /// </summary>
        public static readonly NtruParameters NtruHps4096821 =
            new NtruParameters("ntruhps4096821", new NtruHps4096821());

        /// <summary>
        /// NTRU-HPS parameter set with n = 1229 and q = 4096.
        /// </summary>
        public static readonly NtruParameters NtruHps40961229
            = new NtruParameters("ntruhps40961229", new NtruHps40961229());

        /// <summary>
        /// NTRU-HRSS parameter set with n = 701.
        /// </summary>
        public static readonly NtruParameters NtruHrss701 = new NtruParameters("ntruhrss701", new NtruHrss701());

        /// <summary>
        /// NTRU-HRSS parameter set with n = 1373.
        /// </summary>
        public static readonly NtruParameters NtruHrss1373 = new NtruParameters("ntruhrss1373", new NtruHrss1373());

        /// <summary>
        /// Currently selected parameter set
        /// </summary>
        internal readonly NtruParameterSet ParameterSet;

        private readonly string _name;

        private NtruParameters(string name, NtruParameterSet parameterSet)
        {
            _name = name;
            ParameterSet = parameterSet;
        }

        public string Name => _name;

        public int DefaultKeySize => ParameterSet.SharedKeyBytes * 8;
    }
}