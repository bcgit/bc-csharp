namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public static class Hss
    {
        // TODO[api] Remove
        public static HssPrivateKeyParameters GenerateHssKeyPair(HssKeyGenerationParameters parameters) =>
            LmsEngine.GenerateHssKeyPair(parameters);

        // TODO[api] Remove
        public static void IncrementIndex(HssPrivateKeyParameters keyPair) => keyPair.IncrementIndex();

        // TODO[api] Remove
        public static void RangeTestKeys(HssPrivateKeyParameters keyPair) => keyPair.RangeTestKeys();

        // TODO[api] Remove
        public static HssSignature GenerateSignature(HssPrivateKeyParameters keyPair, byte[] message) =>
            LmsEngine.GenerateHssSignature(keyPair, message);

        // TODO[api] Remove. Its only caller was the one-step form above, which now signs through LmsEngine.
        public static HssSignature GenerateSignature(int L, LmsContext context)
        {
            return new HssSignature(L - 1, context.SignedPubKeys, LmsEngine.GenerateSign(context));
        }

        // TODO[api] Remove
        public static bool VerifySignature(HssPublicKeyParameters publicKey, HssSignature signature, byte[] message) =>
            LmsEngine.VerifyHssSignature(publicKey, signature, message);
    }
}
