using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// NTRU-HRSS parameter set with n = 1373.
    /// </summary>
    /// <seealso cref="NtruHrssParameterSet"></seealso>
    internal class NtruHrss1373
        : NtruHrssParameterSet
    {
        // Category 5 (local model) - KATs basementd on 256 bit
        internal NtruHrss1373()
            : base(1373, 14, 32, 32, 32)
        { }

        internal override Polynomial CreatePolynomial() => new Hrss1373Polynomial(this);
    }
}
