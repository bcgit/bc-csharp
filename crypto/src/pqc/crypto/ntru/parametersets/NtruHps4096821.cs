
using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// NTRU-HPS parameter set with n = 821 and q = 4096.
    /// </summary>
    /// <seealso cref="NtruHpsParameterSet"/>
    internal class NtruHps4096821
        : NtruHpsParameterSet
    {
        // Category 5 (local model)
        internal NtruHps4096821()
            : base(821, 12, 32, 32, 32)
        { }


        internal override Polynomial CreatePolynomial() => new Hps4096Polynomial(this);
    }

}
