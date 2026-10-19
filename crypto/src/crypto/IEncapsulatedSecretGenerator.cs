namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Implemented by classes that generate a secret together with its encapsulation for a recipient.
    /// </summary>
    public interface IEncapsulatedSecretGenerator
    {
        /// <summary>
        /// Generate an exchange pair based on the recipient public key.
        /// </summary>
        /// <param name="recipientKey"></param>
        /// <returns> An SecretWithEncapsulation derived from the recipient public key.</returns>
        ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey);
    }
}