namespace Org.BouncyCastle.Crypto
{
    /// <summary>Interface for key wrapping algorithms.</summary>
    public interface IWrapper
    {
        /// <summary>The name of the algorithm this cipher implements.</summary>
        string AlgorithmName { get; }

        /// <summary>Initialise the wrapper.</summary>
        /// <param name="forWrapping">true for wrapping, false for unwrapping.</param>
        /// <param name="parameters">The key and any other parameters.</param>
        void Init(bool forWrapping, ICipherParameters parameters);

        /// <summary>Wrap a key.</summary>
        /// <param name="input">The buffer holding the key.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the key starts.</param>
        /// <param name="length">The length of the key.</param>
        /// <returns>The wrapped key.</returns>
        byte[] Wrap(byte[] input, int inOff, int length);

        /// <summary>Unwrap a key.</summary>
        /// <param name="input">The buffer holding the wrapped key.</param>
        /// <param name="inOff">The offset into <paramref name="input"/> at which the wrapped key starts.</param>
        /// <param name="length">The length of the wrapped key.</param>
        /// <returns>The unwrapped key.</returns>
        byte[] Unwrap(byte[] input, int inOff, int length);
    }
}
