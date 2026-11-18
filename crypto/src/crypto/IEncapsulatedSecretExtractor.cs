namespace Org.BouncyCastle.Crypto
{
    /// <summary>Implemented by classes that extract the secret from a key encapsulation.</summary>
    public interface IEncapsulatedSecretExtractor
    {
        /// <summary>
        /// Extract the secret based on the recipient private key.
        /// </summary>
        /// <param name="encapsulation"> the encapsulated secret.</param>
        byte[] ExtractSecret(byte[] encapsulation);

        /// <summary>
        /// The length in bytes of the encapsulation.
        /// </summary>
        int EncapsulationLength { get;  }
    }
}