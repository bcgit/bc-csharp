namespace Org.BouncyCastle.Crypto
{
    /// <summary>Interface for key derivation functions that are based on a message authentication code.</summary>
    public interface IMacDerivationFunction
        : IDerivationFunction
    {
        /// <summary>Gets the mac.</summary>
        IMac Mac { get; }
    }
}
