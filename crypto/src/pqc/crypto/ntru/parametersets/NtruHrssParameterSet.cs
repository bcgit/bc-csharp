using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// Abstract class for NTRU-HRSS parameter classes.
    /// <para/>
    /// The naming convention for the classes is {@codeNtruhrss[n]"/>. e.g. <see cref="NtruHrss701"/> has n = 701.
    /// </summary>
    /// <seealso cref="NtruHrss701"></seealso>
    /// <seealso cref="https://ntru.org/f/ntru-20190330.pdf">NTRU specification document section 1.3.3</seealso>
    internal class NtruHrssParameterSet : NtruParameterSet
    {
        private protected NtruHrssParameterSet(int n, int logQ, int seedBytes, int prfKeyBytes, int sharedKeyBytes) :
            base(n, logQ, seedBytes, prfKeyBytes, sharedKeyBytes)
        {
        }

        internal override Polynomial CreatePolynomial()
        {
            return new HrssPolynomial(this);
        }

        internal override int SampleFgBytes()
        {
            return 2 * SampleIidBytes();
        }

        internal override int SampleRmBytes()
        {
            return 2 * SampleIidBytes();
        }
    }
}