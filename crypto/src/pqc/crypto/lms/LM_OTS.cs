using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public static class LMOts
    {
        // Signed, since that is what U16Str takes; the value written is the RFC 8554 typecode either way
        private const short D_PBLC = unchecked((short)0x8080);

        // Offsets into the buffer a Winternitz chain is iterated in, which holds one hash input throughout:
        //
        //     I (16) || u32str(q) (4) || u16str(i) (2) || u8str(j) (1) || tmp (n)
        //     0                  16              ITER_K          ITER_J  ITER_PREV
        //
        // Only the chain index i, the step j and the previous value change as the chains are walked, so the
        // identifier and the leaf number are written once and the whole buffer is hashed in place.
        private const int ITER_K = 20;
        private const int ITER_J = 22;
        private const int ITER_PREV = 23;

        internal const int SEED_RANDOMISER_INDEX = ~2;
        internal const short D_MESG = unchecked((short)0x8181);

        public static int Coef(byte[] S, int i, int w)
        {
            int index = (i * w) / 8;
            int digitsPerByte = 8 / w;
            int shift = w * (~i & (digitsPerByte - 1));
            int mask = (1 << w) - 1;

            return (S[index] >> shift) & mask;
        }

        public static int Cksm(byte[] S, int sLen, LMOtsParameters parameters)
        {
            int sum = 0;

            int w = parameters.W;

            // NB assumption about size of "w" not overflowing integer.
            int maxDigit = (1 << w) - 1;
            int digitCount = sLen * 8 / w;

            for (int i = 0; i < digitCount; i++)
            {
                sum = sum + maxDigit - Coef(S, i, w);
            }
            return sum << parameters.Ls;
        }

        /// <summary>Append the checksum of the first <c>n</c> bytes of <paramref name="Q"/> to them, as the two
        /// bytes the chains after the message digest carry (RFC 8554 sec. 4.5).</summary>
        private static void AppendCksm(byte[] Q, int n, LMOtsParameters parameters)
        {
            int cs = Cksm(Q, n, parameters);
            Pack.UInt16_To_BE((ushort)cs, Q, n);
        }

        // TODO[api] Remove. Nothing calls this: the key derives its own public key.
        public static LMOtsPublicKey LmsOtsGeneratePublicKey(LMOtsPrivateKey privateKey) =>
            privateKey.GeneratePublicKey();

        internal static byte[] LmsOtsGeneratePublicKey(LMOtsParameters parameters, byte[] I, int q, byte[] masterSecret)
        {
            //
            // Start hash that computes the final value.
            //
            int p = parameters.P;
            int n = parameters.N;
            int maxDigit = (1 << parameters.W) - 1;

            IDigest publicKeyDigest = LmsUtilities.GetDigest(parameters);
            Composer.Compose()
                .Bytes(I)
                .U32Str(q)
                .U16Str(D_PBLC)
                // I || u32str(q) || u16str(D_PBLC) is already 22 bytes, so this pads nothing; it states the length
                .PadUntil(0, 22)
                .BuildTo(publicKeyDigest);

            IDigest chainDigest = LmsUtilities.GetDigest(parameters);

            byte[] buf = Composer.Compose()
                .Bytes(I)
                .U32Str(q)
                .PadUntil(0, ITER_PREV + n)
                .Build();
            Debug.Assert(buf.Length == ITER_PREV + n);

            SeedDerive derive = new SeedDerive(I, masterSecret, LmsUtilities.GetDigest(parameters))
            {
                Q = q,
                J = 0,
            };

            for (ushort i = 0; i < p; i++)
            {
                derive.DeriveSeed(i < p - 1, buf, ITER_PREV); // Private Key!
                Pack.UInt16_To_BE(i, buf, ITER_K);
                for (int j = 0; j < maxDigit; j++)
                {
                    buf[ITER_J] = (byte)j;
                    chainDigest.BlockUpdate(buf, 0, ITER_PREV + n);
                    chainDigest.DoFinal(buf, ITER_PREV);
                }
                publicKeyDigest.BlockUpdate(buf, ITER_PREV, n);
            }

            byte[] K = new byte[publicKeyDigest.GetDigestSize()];
            publicKeyDigest.DoFinal(K, 0);
            return K;
        }

        // TODO[api] Rename
        // TODO[api] Remove on promotion
        //
        // Not marked obsolete, although the name alone earns it: this is the only public route from a message to
        // an LM-OTS signature, since the Q it computes in between comes from the internal LmsContext.CollectQ.
        // Deprecating it would need that step made public first, which is only worth doing if standalone LM-OTS
        // signing has users - RFC 8554 does not offer it as a signature scheme in its own right - so it waits for
        // the promotion that makes this whole class internal.
        public static LMOtsSignature lm_ots_generate_signature(LMSigParameters sigParams, LMOtsPrivateKey privateKey,
            byte[][] path, byte[] message, bool preHashed)
        {
            // The randomizer C is an input to Q and is carried in the signature for the verifier to reuse, so a
            // caller supplying Q must supply the C it hashed into it; there is no parameter here to receive it.
            if (preHashed)
                throw new ArgumentException("pre-hashed signing must use LMOtsGenerateSignature", nameof(preHashed));

            //
            // Add the randomizer.
            //
            LmsContext qCtx = privateKey.GetSignatureContext(sigParams, path);

            LmsUtilities.ByteArray(message, 0, message.Length, qCtx);

            byte[] Q = qCtx.CollectQ(privateKey.Parameters);

            return LMOtsGenerateSignature(privateKey, Q, qCtx.C);
        }

        public static LMOtsSignature LMOtsGenerateSignature(LMOtsPrivateKey privateKey, byte[] Q, byte[] C)
        {
            LMOtsParameters parameters = privateKey.Parameters;

            int n = parameters.N;
            int p = parameters.P;
            int w = parameters.W;

            byte[] y = new byte[p * n];

            IDigest chainDigest = LmsUtilities.GetDigest(parameters);

            SeedDerive derive = privateKey.GetDerivationFunction();

            AppendCksm(Q, n, parameters);

            byte[] buf = Composer.Compose()
                .Bytes(privateKey.InternalI)
                .U32Str(privateKey.Q)
                .PadUntil(0, ITER_PREV + n)
                .Build();
            Debug.Assert(buf.Length == ITER_PREV + n);

            derive.J = 0;
            for (ushort i = 0; i < p; i++)
            {
                Pack.UInt16_To_BE(i, buf, ITER_K);
                derive.DeriveSeed(i < p - 1, buf, ITER_PREV);
                int a = Coef(Q, i, w);
                for (int j = 0; j < a; j++)
                {
                    buf[ITER_J] = (byte)j;
                    chainDigest.BlockUpdate(buf, 0, ITER_PREV + n);
                    chainDigest.DoFinal(buf, ITER_PREV);
                }
                Array.Copy(buf, ITER_PREV, y, n * i, n);
            }

            return new LMOtsSignature(parameters, C, y);
        }

        // TODO[api] Remove on promotion
        public static bool LMOtsValidateSignature(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] message,
            bool prehashed)
        {
            // This entry point always hashes the message itself; a caller holding Q needs the context-based
            // LMOtsValidateSignatureCalculate overload.
            if (prehashed)
                throw new ArgumentException("pre-hashed verification must use an LmsContext", nameof(prehashed));

            if (!signature.ParamType.Equals(publicKey.Parameters))
                throw new LmsException("public key and signature ots types do not match");

            return Arrays.AreEqual(LMOtsValidateSignatureCalculate(publicKey, signature, message), publicKey.InternalK);
        }

        // TODO[api] Remove on promotion
        public static byte[] LMOtsValidateSignatureCalculate(LMOtsPublicKey publicKey, LMOtsSignature signature,
            byte[] message)
        {
            LmsContext ctx = publicKey.CreateOtsContext(signature);

            LmsUtilities.ByteArray(message, ctx);

            return ctx.CalculateKc();
        }

        // TODO[api] Remove on promotion
        public static byte[] LMOtsValidateSignatureCalculate(LmsContext context) => context.CalculateKc();

        /// <summary>
        /// Kc, the LM-OTS public key a signature computes for itself: each Winternitz chain is walked from the
        /// step the signature stopped at to the end, and the ends are hashed together (RFC 8554 sec. 4.6). It
        /// matches the public key's own K exactly when the signature is valid for the message Q came from.
        /// </summary>
        /// <param name="Q">The message hash, with room for the checksum this appends.</param>
        internal static byte[] CalculateKc(LMOtsPublicKey publicKey, LMOtsSignature signature, byte[] Q)
        {
            LMOtsParameters parameters = publicKey.Parameters;

            int n = parameters.N;
            int w = parameters.W;
            int p = parameters.P;

            AppendCksm(Q, n, parameters);

            byte[] I = publicKey.InternalI;
            int q = publicKey.Q;

            IDigest publicKeyDigest = LmsUtilities.GetDigest(parameters);
            LmsUtilities.ByteArray(I, publicKeyDigest);
            LmsUtilities.U32Str(q, publicKeyDigest);
            LmsUtilities.U16Str(D_PBLC, publicKeyDigest);

            byte[] buf = Composer.Compose()
                .Bytes(I)
                .U32Str(q)
                .PadUntil(0, ITER_PREV + n)
                .Build();
            Debug.Assert(buf.Length == ITER_PREV + n);

            int maxDigit = (1 << w) - 1;

            byte[] y = signature.InternalY;

            IDigest chainDigest = LmsUtilities.GetDigest(parameters);
            for (ushort i = 0; i < p; i++)
            {
                Pack.UInt16_To_BE(i, buf, ITER_K);
                Array.Copy(y, i * n, buf, ITER_PREV, n);
                int a = Coef(Q, i, w);

                for (int j = a; j < maxDigit; j++)
                {
                    buf[ITER_J] = (byte)j;
                    chainDigest.BlockUpdate(buf, 0, ITER_PREV + n);
                    chainDigest.DoFinal(buf, ITER_PREV);
                }

                publicKeyDigest.BlockUpdate(buf, ITER_PREV, n);
            }

            byte[] K = new byte[n];
            publicKeyDigest.DoFinal(K, 0);

            return K;
        }
    }
}
