
using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// NTRU-HPS parameter set with n = 1229 and q = 4096.
    /// </summary>
    /// <seealso cref="NtruHpsParameterSet"/>
    internal class NtruHps40961229: NtruHpsParameterSet
    {
        // Category 5 (local model)
        public NtruHps40961229()
            : base(1229, 12, 32, 32, 32) { }

        internal override Polynomial CreatePolynomial() => new Hps4096Polynomial(this);
    }
}
