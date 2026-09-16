using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public static class Hss
    {
        public static HssPrivateKeyParameters GenerateHssKeyPair(HssKeyGenerationParameters parameters)
        {
            //
            // LmsPrivateKey can derive and hold the public key so we just use an array of those.
            //
            LmsPrivateKeyParameters[] keys = new LmsPrivateKeyParameters[parameters.Depth];
            LmsSignature[] sig = new LmsSignature[parameters.Depth - 1];

            var rootLms = parameters.GetLmsParameters(0);

            byte[] masterSecret = SecureRandom.GetNextBytes(parameters.Random, rootLms.LMSigParameters.M);
            byte[] I = SecureRandom.GetNextBytes(parameters.Random, 16);

            //
            // Set the HSS key up with a valid root LMSPrivateKeyParameters and placeholders for the remaining LMS keys.
            // The placeholders pass enough information to allow the HSSPrivateKeyParameters to be properly reset to an
            // index of zero. Rather than repeat the same reset-to-index logic in this static method.
            //

            keys[0] = new LmsPrivateKeyParameters(rootLms, 0, I, 1 << rootLms.LMSigParameters.H, masterSecret);

            long hssKeyMaxIndex = 1L << rootLms.LMSigParameters.H;

            for (int t = 1; t < keys.Length; t++)
            {
                var lms = parameters.GetLmsParameters(t);

                keys[t] = new LmsPrivateKeyParameters(lms, 1 << lms.LMSigParameters.H);

                hssKeyMaxIndex <<= lms.LMSigParameters.H;
            }

            // if this has happened we're trying to generate a really large key
            // we'll use MAX_VALUE so that it's at least usable until someone upgrades the structure.
            if (hssKeyMaxIndex == 0)
            {
                hssKeyMaxIndex = long.MaxValue;
            }

            return new HssPrivateKeyParameters(parameters.Depth, keys, sig, 0, hssKeyMaxIndex);
        }

        /**
         * Increments an HSS private key without doing any work on it.
         * HSS private keys are automatically incremented when used to create signatures.
         * <p/>
         * The HSS private key is ranged tested before this incrementation is applied.
         * LMS keys will be replaced as required.
         *
         * @param keyPair
         */
        public static void IncrementIndex(HssPrivateKeyParameters keyPair)
        {
            lock (keyPair)
            {
                RangeTestKeys(keyPair);
                keyPair.IncIndex();
                keyPair.GetKey(keyPair.Level - 1).IncIndex();
            }
        }

        public static void RangeTestKeys(HssPrivateKeyParameters keyPair)
        {
            lock (keyPair)
            {
                if (keyPair.GetIndex() >= keyPair.IndexLimit)
                {
                    throw new ExhaustedPrivateKeyException(
                        "hss private key" + (keyPair.IsShard() ? " shard" : "") + " is exhausted");
                }

                int L = keyPair.Level;
                int d = L;
                var prv = keyPair.GetKeys();
                while (true)
                {
                    LmsPrivateKeyParameters key = prv[d - 1];

                    // The whole tree, not the key's own maxQ: a component key given a narrower limit keeps it, and
                    // replacing the level would hand back a full tree in its place
                    // (IndexAndComponentIndexClaimedTogether). >= rather than ==: an index above 2^h steps straight
                    // over an equality test (bc-java github #2414). Decode now rejects such a q, so this is belt
                    // and braces.
                    if (key.GetIndex() < 1 << key.SigParameters.H)
                        break;

                    if (--d == 0)
                        throw new ExhaustedPrivateKeyException("hss private key" + (keyPair.IsShard() ? " shard" : "") +
                            " is exhausted the maximum limit for this HSS private key");
                }

                if (d < L)
                {
                    keyPair.ReplaceExhaustedKeys(d);
                }
            }
        }

        public static HssSignature GenerateSignature(HssPrivateKeyParameters keyPair, byte[] message)
        {
            // The key claims its own index and the bottom key's one-time index under the one monitor; doing
            // the claim here as well would reopen the window between the two.
            LmsContext context = keyPair.GenerateLmsContext();

            context.BlockUpdate(message, 0, message.Length);

            return GenerateSignature(keyPair.Level, context);
        }

        public static HssSignature GenerateSignature(int L, LmsContext context)
        {
            return new HssSignature(L - 1, context.SignedPubKeys, LmsEngine.GenerateSign(context));
        }

        public static bool VerifySignature(HssPublicKeyParameters publicKey, HssSignature signature, byte[] message)
        {
            int Nspk = signature.LMinus1;
            if (Nspk + 1 != publicKey.Level)
                return false;

            var signedPubKeys = signature.SignedPubKeys;

            // Each level's public key is verified under the level above it, starting from the HSS public key
            LmsPublicKeyParameters key = publicKey.LmsPublicKey;

            for (int i = 0; i < Nspk; i++)
            {
                LmsSignedPubKey signedPubKey = signedPubKeys[i];
                LmsPublicKeyParameters pub = signedPubKey.PublicKey;

                if (!LmsEngine.VerifySignature(key, signedPubKey.Signature, pub))
                    return false;

                key = pub;
            }

            // The bottom level signs the message itself
            return LmsEngine.VerifySignature(key, signature.Signature, message);
        }
    }
}
