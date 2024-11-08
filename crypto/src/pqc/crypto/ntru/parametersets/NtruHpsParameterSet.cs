using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// Abstract class for NTRU-HPS parameter classes.
    /// <para/>
    /// The naming convention for the classes is <c>NTRUHPS[q][n]</c>. e.g. <see cref="NtruHps2048509"/> has n = 509 and q = 2048.
    /// </summary>
    /// <seealso cref="NtruHps2048509"></seealso>
    /// <seealso cref="NtruHps2048677"></seealso>
    /// <seealso cref="NtruHps4096821"></seealso>
    /// <seealso cref="https://ntru.org/f/ntru-20190330.pdf">NTRU specification document section 1.3.2</seealso>
    internal class NtruHpsParameterSet : NtruParameterSet
    {
        private protected NtruHpsParameterSet(int n, int logQ, int seedBytes, int prfKeyBytes, int sharedKeyBytes) :
            base(n, logQ, seedBytes, prfKeyBytes, sharedKeyBytes)
        {
        }

        internal override Polynomial CreatePolynomial()
        {
            return new HpsPolynomial(this);
        }

        internal override int SampleFgBytes()
        {
            return SampleIidBytes() + SampleFixedTypeBytes();
        }

        internal override int SampleRmBytes()
        {
            return SampleIidBytes() + SampleFixedTypeBytes();
        }

        internal int Weight()
        {
            return Q() / 8 - 2;
        }
    }
}