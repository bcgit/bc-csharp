using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets
{
    /// <summary>
    /// Abstract class for all NTRU parameter sets.
    /// </summary>
    /// <seealso cref="NtruHpsParameterSet"></seealso>
    /// <seealso cref="NtruHrssParameterSet"></seealso>
    /// <seealso cref="https://ntru.org/f/ntru-20190330.pdf">NTRU specification document"></seealso>
    internal abstract class NtruParameterSet
    {
        /// <summary>
        /// n
        /// </summary>
        /// <returns> n is a prime and both 2 and 3 are of order n − 1 in (Z/n)×</returns>
        internal int N { get; }

        /// <summary>
        /// logq
        /// </summary>
        /// <returns> log2(q)</returns>
        internal int LogQ { get; }

        /// <summary>
        /// The number of random bytes consumed by keygen.
        /// </summary>
        internal int SeedBytes { get; }

        /// <summary>
        /// The number of bytes used to key the implicit rejection mechanism.
        /// </summary>
        internal int PrfKeyBytes { get; }
        internal int SharedKeyBytes { get; }

        internal NtruParameterSet(int n, int logQ, int seedBytes, int prfKeyBytes, int sharedKeyBytes)
        {
            N = n;
            LogQ = logQ;
            SeedBytes = seedBytes;
            PrfKeyBytes = prfKeyBytes;
            SharedKeyBytes = sharedKeyBytes;
        }

        /// <summary>
        /// Creates a polynomial based on this parameter set.
        /// </summary>
        /// <returns> an instance of <see cref="Polynomial"/></returns>
        internal abstract Polynomial CreatePolynomial();

        /// <summary>
        /// q
        /// </summary>
        /// <returns> q is a power of two</returns>
        internal int Q()
        {
            return 1 << LogQ;
        }

        internal int SampleIidBytes()
        {
            return N - 1;
        }

        internal int SampleFixedTypeBytes()
        {
            return (30 * (N - 1) + 7) / 8;
        }

        internal abstract int SampleFgBytes();

        internal abstract int SampleRmBytes();

        internal int PackDegree()
        {
            return N - 1;
        }

        internal int PackTrinaryBytes()
        {
            return (PackDegree() + 4) / 5;
        }

        /// <summary>
        /// The number of bytes in a plaintext for the DPKE.
        /// </summary>
        internal int OwcpaMsgBytes()
        {
            return 2 * PackTrinaryBytes();
        }

        /// <summary>
        /// The number of bytes in a public key for the DPKE.
        /// </summary>
        internal int OwcpaPublicKeyBytes()
        {
            return (LogQ * PackDegree() + 7) / 8;
        }

        /// <summary>
        /// The number of bytes in a private key for the DPKE.
        /// </summary>
        internal int OwcpaSecretKeyBytes()
        {
            return 2 * PackTrinaryBytes() + OwcpaPublicKeyBytes();
        }

        /// <summary>
        /// The number of bytes in a ciphertext for the DPKE.
        /// </summary>
        internal int OwcpaBytes()
        {
            return (LogQ * PackDegree() + 7) / 8;
        }

        /// <summary>
        /// The number of bytes in a public key for the KEM.
        /// </summary>
        internal int NtruPublicKeyBytes()
        {
            return OwcpaPublicKeyBytes();
        }

        /// <summary>
        /// The number of bytes in a private key for the KEM.
        /// </summary>
        internal int NtruSecretKeyBytes()
        {
            return OwcpaSecretKeyBytes() + PrfKeyBytes;
        }

        /// <summary>
        /// The number of bytes in a ciphertext for the KEM.
        /// </summary>
        internal int NtruCiphertextBytes()
        {
            return OwcpaBytes();
        }
    }
}