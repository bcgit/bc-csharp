using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>The interface that basic Diffie-Hellman implementations conform to.</summary>
    public interface IBasicAgreement
    {
        /// <summary>Initialise the agreement engine.</summary>
        void Init(ICipherParameters parameters);

        /// <summary>Return the field size for the agreement algorithm in bytes.</summary>
        int GetFieldSize();

        /// <summary>
        /// Given a public key from a given party calculate the next message in the agreement sequence.
        /// </summary>
        BigInteger CalculateAgreement(ICipherParameters pubKey);
    }
}
