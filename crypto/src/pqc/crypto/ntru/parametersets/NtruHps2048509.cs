namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// NTRU-HPS parameter set with n = 509 and q = 2048.
    /// </summary>
    /// <seealso cref="NtruHpsParameterSet"/>
    internal class NtruHps2048509 : NtruHpsParameterSet
    {
        internal NtruHps2048509() : base(509, 11, 32, 32, 32)
        {
        }
    }
}