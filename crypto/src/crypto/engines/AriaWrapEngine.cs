namespace Org.BouncyCastle.Crypto.Engines
{
    /// <remarks>
    /// An implementation of the ARIA Key Wrapper from the NIST Key Wrap Specification.
    /// <p/>
    /// For further details see: <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
    /// </remarks>
    public class AriaWrapEngine
		: Rfc3394WrapEngine
	{
        /// <summary>
        /// Create a regular AriaWrapEngine specifying the encrypt for wrapping, decrypt for unwrapping.
        /// </summary>
        public AriaWrapEngine()
			: base(new AriaEngine())
		{
		}

        /// <summary>
        /// Create an AriaWrapEngine where the underlying cipher is (optionally) set to decrypt for wrapping, encrypt for
        /// unwrapping.
        /// </summary>
        /// <param name="useReverseDirection">true if underlying cipher should be used in decryption mode, false
        /// otherwise.</param>
        public AriaWrapEngine(bool useReverseDirection)
            : base(new AriaEngine(), useReverseDirection)
        {
        }
    }
}
