namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>Hierarchical signature system (HSS) operations, as defined in RFC 8554.</summary>
    // TODO[api] Make internal
    public static class Hss
    {
        /// <summary>Generate an HSS private key (which includes the public key).</summary>
        /// <param name="parameters">The key generation parameters.</param>
        /// <returns>The private key.</returns>
        // TODO[api] Remove
        public static HssPrivateKeyParameters GenerateHssKeyPair(HssKeyGenerationParameters parameters) =>
            HssPrivateKeyParameters.Generate(parameters);

        // TODO[api] Remove
        public static void IncrementIndex(HssPrivateKeyParameters keyPair) => keyPair.IncrementIndex();

        /// <summary>
        /// Check that the private key has signatures left, advancing the hierarchy if the lower levels are exhausted.
        /// </summary>
        /// <param name="keyPair">The private key.</param>
        // TODO[api] Remove
        public static void RangeTestKeys(HssPrivateKeyParameters keyPair) => keyPair.RangeTestKeys();

        /// <summary>Generate an HSS signature of a message.</summary>
        /// <param name="keyPair">The private key.</param>
        /// <param name="message">The message.</param>
        /// <returns>The signature.</returns>
        // TODO[api] Remove
        public static HssSignature GenerateSignature(HssPrivateKeyParameters keyPair, byte[] message) =>
            LmsEngine.GenerateHssSignature(keyPair, message);

        /// <summary>Generate an HSS signature using a prepared context.</summary>
        /// <param name="L">The number of levels.</param>
        /// <param name="context">The context holding the message digest state.</param>
        /// <returns>The signature.</returns>
        // TODO[api] Remove. Its only caller was the one-step form above, which now signs through LmsEngine.
        public static HssSignature GenerateSignature(int L, LmsContext context)
        {
            return new HssSignature(L - 1, context.SignedPubKeys, LmsEngine.GenerateSign(context));
        }

        /// <summary>Verify an HSS signature of a message.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="message">The message.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        // TODO[api] Remove
        public static bool VerifySignature(HssPublicKeyParameters publicKey, HssSignature signature, byte[] message) =>
            LmsEngine.VerifyHssSignature(publicKey, signature, message);
    }
}
