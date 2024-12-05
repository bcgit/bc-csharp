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

        private readonly string m_name;
        private readonly NtruParameterSet m_parameterSet;

        private NtruParameters(string name, NtruParameterSet parameterSet)
        {
            m_name = name;
            m_parameterSet = parameterSet;
        }

        public string Name => m_name;

        internal NtruParameterSet ParameterSet => m_parameterSet;

        internal int PrivateKeyLength => ParameterSet.NtruSecretKeyBytes();

        internal int PublicKeyLength => ParameterSet.NtruPublicKeyBytes();

        // TODO[pqc] bc-java uses 'SessionKeySize' for this
        public int DefaultKeySize => ParameterSet.SharedKeyBytes * 8;
    }
}
