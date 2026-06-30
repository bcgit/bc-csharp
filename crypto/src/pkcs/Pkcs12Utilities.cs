using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>Utility class for re-encoding PKCS#12 files to definite length.</summary>
    public class Pkcs12Utilities
    {
        /// <summary>Just re-encode the outer layer of the PKCS#12 file to definite length encoding.</summary>
        /// <param name="berPkcs12File">original PKCS#12 file.</param>
        /// <returns>a byte array representing the DL encoding of the PFX structure.</returns>
        /// <exception cref="IOException"/>
        public static byte[] ConvertToDefiniteLength(byte[] berPkcs12File) => DLEncode(Pfx.GetInstance(berPkcs12File));

        /// <summary>Re-encode the PKCS#12 structure to definite length encoding at the inner layer as well.</summary>
        /// <remarks>The MAC (if present) is recomputed accordingly.</remarks>
        /// <param name="berPkcs12File">original PKCS#12 file.</param>
        /// <param name="passwd">The store password, if any.</param>
        /// <returns>a byte array representing the DL encoding of the PFX structure.</returns>
        /// <exception cref="IOException"/>
        public static byte[] ConvertToDefiniteLength(byte[] berPkcs12File, char[] passwd)
        {
            Pfx pfx = Pfx.GetInstance(berPkcs12File);

            ContentInfo info = pfx.AuthSafe;

            Asn1Object obj = Asn1Object.FromByteArray(GetContentOctets(info));

            var contentOctets = DLEncode(obj);

            info = new ContentInfo(info.ContentType, DerOctetString.WithContents(contentOctets));

            /*
             * TODO This code should be more like Pkcs12Store Load then Save?
             * e.g. verify integrity on Load (retry with wrongPkcs12Zero)
             */
            MacData macData = pfx.MacData;
            if (macData != null)
            {
                if (passwd == null)
                    throw new ArgumentNullException(nameof(passwd), "no password supplied when one expected");

                try
                {
                    var macAlgID = macData.Mac.DigestAlgorithm;
                    int iterations = ValidateIterations(macData.Iterations);

                    byte[] macResult = Pkcs12Store.CalculatePbeMac(macAlgID, macData.MacSalt.GetOctets(), iterations,
                        passwd, wrongPkcs12Zero: false, data: contentOctets);

                    var digInfo = new DigestInfo(macAlgID, DerOctetString.WithContents(macResult));

                    macData = new MacData(digInfo, macData.MacSalt, macData.Iterations);
                }
                catch (Exception e)
                {
                    throw new IOException("error constructing MAC: " + e.ToString());
                }
            }
            else if (passwd != null)
            {
                // TODO Throw exception here (after checking IgnoreUselessPasswordProperty)? See Pkcs12Store.Load.
            }

            pfx = new Pfx(info, macData);

            return DLEncode(pfx);
        }

        internal static Asn1Encodable GetContent(ContentInfo contentInfo) => contentInfo.Content
            ?? throw new Asn1ParsingException("ContentInfo content missing");

        internal static byte[] GetContentOctets(ContentInfo contentInfo) =>
            Asn1OctetString.GetInstance(GetContent(contentInfo)).GetOctets();

        internal static Asn1OctetString GetEncryptedContent(EncryptedData encryptedData) => encryptedData.Content
            ?? throw new Asn1ParsingException("EncryptedContentInfo content missing");

        internal static int ValidateIterations(DerInteger iterations)
        {
            if (iterations == null)
                throw new ArgumentNullException(nameof(iterations));
            if (!iterations.TryGetIntValueExact(out int intValueExact))
                throw new InvalidOperationException("iteration counts >= 2^31 are not suppported");

            return ValidateIterations(intValueExact);
        }

        //internal static int ValidateIterations(BigInteger iterations)
        //{
        //    if (iterations == null)
        //        throw new ArgumentNullException(nameof(iterations));
        //    if (iterations.BitLength > 31)
        //        throw new InvalidOperationException("iteration counts >= 2^31 are not suppported");

        //    return ValidateIterations(iterations.IntValueExact);
        //}

        internal static int ValidateIterations(int iterations)
        {
            if (iterations < 0)
                throw new InvalidOperationException("negative iteration count found");

            int maxIterations = Properties.GetInt32(Properties.Pkcs12MaxIterationCount, 5_000_000);
            if (iterations > maxIterations)
                throw new InvalidOperationException($"iteration count {iterations} greater than {maxIterations}");

            return iterations;
        }

        private static byte[] DLEncode(Asn1Encodable asn1Encodable) => asn1Encodable.GetEncoded(Asn1Encodable.DL);
    }
}
