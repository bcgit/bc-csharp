namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// NTRU-HRSS parameter set with n = 701.
    /// </summary>
    /// <seealso cref="NtruHrssParameterSet"/>
    internal class NtruHrss701 : NtruHrssParameterSet
    {
        // Category 3 (local model) - KATs based on 256 bit
        internal NtruHrss701() : base(701, 13, 32, 32, 32)
        {
        }
    }
}