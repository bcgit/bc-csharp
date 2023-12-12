using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public static class Lms
    {
        internal static ushort D_LEAF = 0x8282;
        internal static ushort D_INTR = 0x8383;

        public static LmsPrivateKeyParameters GenerateKeys(LMSigParameters parameterSet,
            LMOtsParameters lmOtsParameters, int q, byte[] I, byte[] rootSeed)
        {
            //
            // RFC 8554 recommends that digest used in LMS and LMOTS be of the same strength to protect against
            // attackers going after the weaker of the two digests. This is not enforced here!
            //

            // Algorithm 5, Compute LMS private key.

            // Step 1
            // -- Parameters passed in as arguments.


            // Step 2
            if (rootSeed == null || rootSeed.Length < parameterSet.M)
                throw new ArgumentException($"root seed is less than {parameterSet.M}");

            int twoToH = 1 << parameterSet.H;

            return new LmsPrivateKeyParameters(parameterSet, lmOtsParameters, q, I, twoToH, rootSeed);
        }

        public static LmsSignature GenerateSign(LmsPrivateKeyParameters privateKey, byte[] message)
        {
            //
            // Get T from the public key.
            // This may cause the public key to be generated.
            //
            // byte[][] T = new byte[privateKey.getMaxQ()][];

            // Step 2
            LmsContext context = privateKey.GenerateLmsContext();

            context.BlockUpdate(message, 0, message.Length);

            return GenerateSign(context);
        }

        public static LmsSignature GenerateSign(LmsContext context)
        {
            //
            // Get T from the public key.
            // This may cause the public key to be generated.
            //
            // byte[][] T = new byte[privateKey.getMaxQ()][];

            // Step 1.
            LMOtsSignature ots_signature =
                LMOts.LMOtsGenerateSignature(context.PrivateKey, context.GetQ(), context.C);

            return new LmsSignature(context.PrivateKey.Q, ots_signature, context.SigParams, context.Path);
        }

        public static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsSignature S, byte[] message)
        {
            LmsContext context = publicKey.GenerateOtsContext(S);

            LmsUtilities.ByteArray(message, context);

            return VerifySignature(publicKey, context);
        }

        public static bool VerifySignature(LmsPublicKeyParameters publicKey, byte[] S, byte[] message)
        {
            LmsContext context = publicKey.GenerateLmsContext(S);

            LmsUtilities.ByteArray(message, context);

            return VerifySignature(publicKey, context);
        }

        public static bool VerifySignature(LmsPublicKeyParameters publicKey, LmsContext context)
        {
            LmsSignature S = (LmsSignature)context.Signature;
            LMSigParameters lmsParameter = S.SigParameters;
            int h = lmsParameter.H;
            byte[][] path = S.Y;
            byte[] Kc = LMOts.LMOtsValidateSignatureCalculate(context);
            // Step 4
            // node_num = 2^h + q
            int node_num = (1 << h) + S.Q;

            // tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
            byte[] I = publicKey.GetI();
            IDigest H = LmsUtilities.GetDigest(lmsParameter);
            byte[] tmp = new byte[H.GetDigestSize()];

            H.BlockUpdate(I, 0, I.Length);
            LmsUtilities.U32Str(node_num, H);
            LmsUtilities.U16Str((short)D_LEAF, H);
            H.BlockUpdate(Kc, 0, Kc.Length);
            H.DoFinal(tmp, 0);

            int i = 0;

            while (node_num > 1)
            {
                if ((node_num & 1) == 1)
                {
                    // is odd
                    H.BlockUpdate(I, 0, I.Length);
                    LmsUtilities.U32Str(node_num / 2, H);
                    LmsUtilities.U16Str((short)D_INTR, H);
                    H.BlockUpdate(path[i], 0, path[i].Length);
                    H.BlockUpdate(tmp, 0, tmp.Length);
                    H.DoFinal(tmp, 0);
                }
                else
                {
                    H.BlockUpdate(I, 0, I.Length);
                    LmsUtilities.U32Str(node_num / 2, H);
                    LmsUtilities.U16Str((short)D_INTR, H);
                    H.BlockUpdate(tmp, 0, tmp.Length);
                    H.BlockUpdate(path[i], 0, path[i].Length);
                    H.DoFinal(tmp, 0);
                }

                node_num = node_num / 2;
                i++;
                // these two can get out of sync with an invalid signature, we'll
                // try and fail gracefully
                if (i == path.Length && node_num > 1)
                    return false;
            }

            byte[] Tc = tmp;
            return publicKey.MatchesT1(Tc);
        }
    }
}