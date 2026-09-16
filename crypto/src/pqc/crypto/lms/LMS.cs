using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public static class Lms
    {
        // TODO[api] Remove, it only forwards to LmsEngine.GenerateKey
        public static LmsPrivateKeyParameters GenerateKeys(LMSigParameters parameterSet,
            LMOtsParameters lmOtsParameters, int q, byte[] I, byte[] masterSecret)
        {
            return LmsEngine.GenerateKey(new LmsParameters(parameterSet, lmOtsParameters), q, I, masterSecret);
        }

        // TODO[api] Remove. Nothing in the library signs this way, and bc-java has no such method since its
        // promotion; LmsEngine carries a copy for the tests.
        public static LmsSignature GenerateSign(LmsPrivateKeyParameters privateKey, byte[] message) =>
            LmsEngine.GenerateSign(privateKey, message);

        // TODO[api] Remove, it only forwards to LmsEngine
        public static LmsSignature GenerateSign(LmsContext context) => LmsEngine.GenerateSign(context);

        // TODO[api] Remove, it only forwards to LmsEngine; bc-java kept this form package-private at promotion
        public static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature S, byte[] message) =>
            LmsEngine.VerifySignature(publicKey, S, message);

        // TODO[api] Remove, nothing calls it and ILmsContextBasedVerifier already exposes the context route
        public static bool VerifySignature(LmsPublicKeyParameters publicKey, byte[] S, byte[] message)
        {
            LmsContext context = publicKey.GenerateLmsContext(S);

            LmsUtilities.ByteArray(message, context);

            return VerifySignature(publicKey, context);
        }

        // TODO[api] Remove, it only forwards to LmsEngine
        public static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsContext context) =>
            LmsEngine.VerifySignature(publicKey, context);
    }
}