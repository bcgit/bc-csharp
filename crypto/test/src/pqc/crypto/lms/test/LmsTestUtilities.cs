using System.IO;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pqc.Crypto.Lms.Tests
{
    public class LmsTestUtilities
    {
        public static HssPrivateKeyParameters GenerateHssPrivateKey(HssKeyGenerationParameters parameters) =>
            HssPrivateKeyParameters.Generate(parameters);

        /// <summary>Generate a key from the two parameter sets the vectors name it by.</summary>
        /// <remarks>Here for the same reason as the signing helpers below: the library takes the pair as an
        /// <see cref="LmsParameters"/>, and the two-parameter-set form is on its way out of the public API.</remarks>
        public static LmsPrivateKeyParameters GenerateKey(LMSigParameters sigParameters,
            LMOtsParameters otsParameters, int q, byte[] I, byte[] masterSecret)
        {
            int maxQ = 1 << sigParameters.H;
            return new LmsPrivateKeyParameters(sigParameters, otsParameters, q, I, maxQ, masterSecret);
        }

        /// <summary>
        /// Sign a message in one step, the way the RFC 8554 vectors are stated.
        /// </summary>
        /// <remarks>
        /// The tests reach the one-step form through here so that the library method behind it can move or go
        /// without touching every vector test: it is on its way out of the public API, and bc-java dropped it at
        /// promotion. Signing in the library is a context and an update.
        /// </remarks>
        public static LmsSignature GenerateSign(LmsPrivateKeyParameters privateKey, byte[] message) =>
            LmsEngine.GenerateSign(privateKey, message);

        /// <summary>Sign a message in one step with an HSS key, the hierarchy's counterpart of
        /// <see cref="GenerateSign(LmsPrivateKeyParameters, byte[])"/> and here for the same reason.</summary>
        public static HssSignature GenerateHssSignature(HssPrivateKeyParameters privateKey, byte[] message) =>
            LmsEngine.GenerateHssSignature(privateKey, message);

        /// <summary>Verify a signature over a message in one step, the counterpart of
        /// <see cref="GenerateSign(LmsPrivateKeyParameters, byte[])"/> and here for the same reason.</summary>
        public static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature signature, byte[] message) =>
            LmsEngine.VerifySignature(publicKey, signature, message);

        /// <summary>Verify an HSS signature over a message in one step, the counterpart of
        /// <see cref="GenerateHssSignature(HssPrivateKeyParameters, byte[])"/> and here for the same reason.</summary>
        public static bool VerifyHssSignature(HssPublicKeyParameters publicKey, HssSignature signature,
            byte[] message)
        {
            return LmsEngine.VerifyHssSignature(publicKey, signature, message);
        }

        public static byte[] ExtractPrefixedBytes(string vectorFromRFC)
        {
            MemoryStream bos = new MemoryStream();
            byte[] hexByte;
            foreach (string line in vectorFromRFC.Split('\n'))
            {
                int start = line.IndexOf('$');
                if (start > -1)
                {
                    ++start;
                    int end = line.IndexOf('#');
                    string hex;
                    if (end < 0)
                    {
                        hex = line.Substring(start).Trim();
                    }
                    else
                    {
                        hex = line.Substring(start, end - start).Trim();
                    }

                    hexByte = Hex.Decode(hex);
                    bos.Write(hexByte, 0, hexByte.Length);
                }
            }
            return bos.ToArray();
        }
    }
}
