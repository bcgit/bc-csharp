using System;
using System.Collections.Generic;

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

            byte[] rootSeed = SecureRandom.GetNextBytes(parameters.Random,
                parameters.GetLmsParameters(0).LMSigParameters.M);
            byte[] I = SecureRandom.GetNextBytes(parameters.Random, 16);

            //
            // Set the HSS key up with a valid root LMSPrivateKeyParameters and placeholders for the remaining LMS keys.
            // The placeholders pass enough information to allow the HSSPrivateKeyParameters to be properly reset to an
            // index of zero. Rather than repeat the same reset-to-index logic in this static method.
            //

            byte[] zero = new byte[0];

            long hssKeyMaxIndex = 1;
            for (int t = 0; t < keys.Length; t++)
            {
                var lms = parameters.GetLmsParameters(t);
                if (t == 0)
                {
                    keys[t] = new LmsPrivateKeyParameters(
                        lms.LMSigParameters,
                        lms.LMOtsParameters,
                        0,
                        I,
                        1 << lms.LMSigParameters.H,
                        rootSeed,
                        isPlaceholder: false);
                }
                else
                {
                    keys[t] = new LmsPrivateKeyParameters(
                        lms.LMSigParameters,
                        lms.LMOtsParameters,
                        -1,
                        zero,
                        1 << lms.LMSigParameters.H,
                        zero,
                        isPlaceholder: true);
                }
                hssKeyMaxIndex <<= lms.LMSigParameters.H;
            }

            // if this has happened we're trying to generate a really large key
            // we'll use MAX_VALUE so that it's at least usable until someone upgrades the structure.
            if (hssKeyMaxIndex == 0)
            {
                hssKeyMaxIndex = long.MaxValue;
            }

            return new HssPrivateKeyParameters(
                parameters.Depth,
                new List<LmsPrivateKeyParameters>(keys),
                new List<LmsSignature>(sig),
                0, hssKeyMaxIndex);
        }

        /**
         * Increments an HSS private key without doing any work on it.
         * HSS private keys are automatically incremented when when used to create signatures.
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
                keyPair.GetKeys()[keyPair.Level - 1].IncIndex();
            }
        }

        public static void RangeTestKeys(HssPrivateKeyParameters keyPair)
        {
            lock (keyPair)
            {
                if (keyPair.GetIndex() >= keyPair.IndexLimit)
                {
                    // TODO ExhaustedPrivateKeyException
                    throw new Exception(
                        "hss private key" + (keyPair.IsShard() ? " shard" : "") + " is exhausted");
                }

                int L = keyPair.Level;
                int d = L;
                var prv = keyPair.GetKeys();
                while (prv[d - 1].GetIndex() == 1 << prv[d - 1].SigParameters.H)
                {
                    if (--d == 0)
                        // TODO ExhaustedPrivateKeyException
                        throw new Exception("hss private key" + (keyPair.IsShard() ? " shard" : "") +
                            " is exhausted the maximum limit for this HSS private key");
                }

                while (d < L)
                {
                    keyPair.ReplaceConsumedKey(d++);
                }
            }
        }

        public static HssSignature GenerateSignature(HssPrivateKeyParameters keyPair, byte[] message)
        {
            LmsSignedPubKey[] signed_pub_key;
            LmsPrivateKeyParameters nextKey;
            int L = keyPair.Level;

            lock (keyPair)
            {
                RangeTestKeys(keyPair);
                
                var keys = keyPair.GetKeys();
                var sig = keyPair.GetSig();

                nextKey = keyPair.GetKeys()[L - 1];

                // Step 2. Stand in for sig[L-1]
                int i = 0;
                signed_pub_key = new LmsSignedPubKey[L - 1];
                while (i < L - 1)
                {
                    signed_pub_key[i] = new LmsSignedPubKey(sig[i], keys[i + 1].GetPublicKey());
                    ++i;
                }

                //
                // increment the index.
                //
                keyPair.IncIndex();
            }

            LmsContext context = nextKey.GenerateLmsContext().WithSignedPublicKeys(signed_pub_key);

            context.BlockUpdate(message, 0, message.Length);

            return GenerateSignature(L, context);
        }

        public static HssSignature GenerateSignature(int L, LmsContext context)
        {
            return new HssSignature(L - 1, context.SignedPubKeys, Lms.GenerateSign(context));
        }

        public static bool VerifySignature(HssPublicKeyParameters publicKey, HssSignature signature, byte[] message)
        {
            int Nspk = signature.LMinus1;
            if (Nspk + 1 != publicKey.Level)
                return false;

            LmsSignature[] sigList = new LmsSignature[Nspk + 1];
            LmsPublicKeyParameters[] pubList = new LmsPublicKeyParameters[Nspk];

            for (int i = 0; i < Nspk; i++)
            {
                sigList[i] = signature.SignedPubKeys[i].Signature;
                pubList[i] = signature.SignedPubKeys[i].PublicKey;
            }
            sigList[Nspk] = signature.Signature;

            LmsPublicKeyParameters key = publicKey.LmsPublicKey;

            for (int i = 0; i < Nspk; i++)
            {
                LmsSignature sig = sigList[i];
                byte[] msg = pubList[i].ToByteArray();
                if (!Lms.VerifySignature(key, sig, msg))
                    return false;

                try
                {
                    key = pubList[i];
                }
                catch (Exception ex)
                {
                    throw new Exception(ex.Message, ex);
                }
            }
            return Lms.VerifySignature(key, sigList[Nspk], message);
        }
    }
}
