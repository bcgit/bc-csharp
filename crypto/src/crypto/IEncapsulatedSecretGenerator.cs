namespace Org.BouncyCastle.Crypto
{
    public interface IEncapsulatedSecretGenerator
    {
        /// <summary>
        /// Generate secret/encapsulation based on the recipient public key.
        /// </summary>
        /// <param name="recipientKey"></param>
        /// <returns> An SecretWithEncapsulation derived from the recipient public key.</returns>
        ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey);
    }
}