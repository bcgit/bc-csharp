using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public static class LmsUtilities
    {
        public static void U32Str(int n, IDigest d)
        {
            d.Update((byte)(n >> 24));
            d.Update((byte)(n >> 16));
            d.Update((byte)(n >> 8));
            d.Update((byte)(n));
        }

        public static void U16Str(short n, IDigest d)
        {
            d.Update((byte)(n >> 8));
            d.Update((byte)(n));
        }

        public static void ByteArray(byte[] array, IDigest digest)
        {
            digest.BlockUpdate(array, 0, array.Length);
        }

        public static void ByteArray(byte[] array, int start, int len, IDigest digest)
        {
            digest.BlockUpdate(array, start, len);
        }

        public static int CalculateStrength(LmsParameters lmsParameters)
        {
            if (lmsParameters == null)
                throw new ArgumentNullException(nameof(lmsParameters));

            LMSigParameters sigParameters = lmsParameters.LMSigParameters;
            return sigParameters.M << sigParameters.H;
        }

        internal static IDigest GetDigest(LMOtsParameters otsParameters) =>
            CreateDigest(otsParameters.DigestOid, otsParameters.N);

        internal static IDigest GetDigest(LMSigParameters sigParameters) =>
            CreateDigest(sigParameters.DigestOid, sigParameters.M);

        private static IDigest CreateDigest(DerObjectIdentifier oid, int length)
        {
            // TODO Perhaps support length-specified digests directly in DigestUtilities?

            if (NistObjectIdentifiers.IdSha256.Equals(oid))
            {
                IDigest digest = DigestUtilities.GetDigest(NistObjectIdentifiers.IdSha256);

                return length == digest.GetDigestSize() ? digest : new ShortenedDigest(digest, length);
            }

            if (NistObjectIdentifiers.IdShake256Len.Equals(oid))
            {
                // SP 800-208 takes the first 'length' bytes of the XOF output, which is what a fixed-size XOF
                // squeezes. The digest size of SHAKE256 is twice its security parameter, so it is never 'length'.
                IXof xof = (IXof)DigestUtilities.GetDigest(NistObjectIdentifiers.IdShake256);

                return new XofDigest(xof, length);
            }

            throw new LmsException("unrecognized digest OID: " + oid);
        }
    }
}
