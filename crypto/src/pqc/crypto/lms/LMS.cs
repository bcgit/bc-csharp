using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>Leighton-Micali signature (LMS) operations, as defined in RFC 8554.</summary>
    // TODO[api] Make internal
    public static class Lms
    {
        /// <summary>Generate an LMS private key.</summary>
        /// <param name="parameterSet">The LMS parameter set.</param>
        /// <param name="lmOtsParameters">The LM-OTS parameter set.</param>
        /// <param name="q">The index of the next signature to produce.</param>
        /// <param name="I">The key identifier.</param>
        /// <param name="rootSeed">The root seed.</param>
        /// <returns>The private key.</returns>
        /// <exception cref="ArgumentException">The root seed is too short.</exception>
        public static LmsPrivateKeyParameters GenerateKeys(LMSigParameters parameterSet,
            LMOtsParameters lmOtsParameters, int q, byte[] I, byte[] masterSecret)
        {
            return new LmsPrivateKeyParameters(parameterSet, lmOtsParameters, q, I, 1 << parameterSet.H, masterSecret);
        }

        /// <summary>Generate an LMS signature of a message.</summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="message">The message.</param>
        /// <returns>The signature.</returns>
        public static LmsSignature GenerateSign(LmsPrivateKeyParameters privateKey, byte[] message) =>
            LmsEngine.GenerateSign(privateKey, message);

        /// <summary>Generate an LMS signature from a context into which the message has been written.</summary>
        /// <param name="context">The context.</param>
        /// <returns>The signature.</returns>
        public static LmsSignature GenerateSign(LmsContext context) => LmsEngine.GenerateSign(context);

        /// <summary>Verify an LMS signature of a message.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="S">The signature.</param>
        /// <param name="message">The message.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        public static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature S, byte[] message) =>
            LmsEngine.VerifySignature(publicKey, S, message);

        /// <summary>Verify an encoded LMS signature of a message.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="S">The encoded signature.</param>
        /// <param name="message">The message.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        public static bool VerifySignature(LmsPublicKeyParameters publicKey, byte[] S, byte[] message)
        {
            LmsContext context = publicKey.GenerateLmsContext(S);

            LmsUtilities.ByteArray(message, context);

            return VerifySignature(publicKey, context);
        }

        /// <summary>Verify an LMS signature using a context into which the message has been written.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="context">The context.</param>
        /// <returns>true if the signature is valid, false otherwise.</returns>
        public static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsContext context) =>
            LmsEngine.VerifySignature(publicKey, context);
    }
}