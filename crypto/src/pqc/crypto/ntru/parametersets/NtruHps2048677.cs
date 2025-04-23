namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// NTRU-HPS parameter set with n = 677 and q = 2048.
    /// </summary>
    /// <seealso cref="NtruHpsParameterSet"/>
    internal class NtruHps2048677 : NtruHpsParameterSet
    {
        internal NtruHps2048677() : base(677, 11, 32, 32, 32)
        {
        }
    }
}