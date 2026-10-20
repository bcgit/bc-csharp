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
        private const int DefaultMaxIterationCount = 5_000_000;

        /// <summary>
        /// The PBE iteration count used when writing a PKCS#12 file, and half the count used for its integrity MAC.
        /// </summary>
        /// <remarks>
        /// <b>Do not raise this to 600,000 or more without testing on Windows:</b> Windows currently reports an error
        /// importing a PKCS#12 file whose key and certificate encryption uses a PBE iteration count of 600,000 or
        /// greater (it accepts 600,000 for the MAC). That limit may change in later Windows releases, so recheck it
        /// before moving this.
        /// </remarks>
        private const int DefaultStoreIterationCount = 300_000;

        /// <summary>
        /// Largest count <see cref="Properties.Pkcs12StoreIterationCount"/> may name. Half of
        /// <see cref="DefaultMaxIterationCount"/> so that the doubled MAC count still passes
        /// <see cref="ValidateIterations(int)"/> on load: a file BC writes must be one BC can read back with the
        /// read-side cap left at its default.
        /// </summary>
        private const int MaxStoreIterationCount = 2_500_000;

        /// <summary>
        /// The shortest MAC salt written, whatever a loaded file declared - PKCS#12's traditional size.
        /// </summary>
        private const int MinMacSaltLength = 8;

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

        /// <summary>
        /// The PBE iteration count to write with, <see cref="DefaultStoreIterationCount"/> unless
        /// <see cref="Properties.Pkcs12StoreIterationCount"/> names a usable value. A value outside
        /// 1..<see cref="MaxStoreIterationCount"/> is ignored, so a mistyped property fails towards the default rather
        /// than towards a file with no PBE work in it.
        /// </summary>
        internal static int GetDefaultStoreIterationCount()
        {
            int iterations = Properties.GetInt32(Properties.Pkcs12StoreIterationCount, DefaultStoreIterationCount);
            if (iterations < 1 || iterations > MaxStoreIterationCount)
                return DefaultStoreIterationCount;

            return iterations;
        }

        internal static Asn1OctetString GetEncryptedContent(EncryptedData encryptedData) => encryptedData.Content
            ?? throw new Asn1ParsingException("EncryptedContentInfo content missing");

        /// <summary>
        /// Return the length of the MacData salt to write, given the length a loaded file declared. A file keeps its
        /// own length where that is at least <see cref="MinMacSaltLength"/>, so a file from another implementation
        /// round trips, but a file declaring no salt at all - or one too short to be one - does not hand that on to a
        /// file written here.
        /// </summary>
        /// <param name="saltLength">The MAC salt length the loaded file declared.</param>
        /// <returns>The length to write.</returns>
        internal static int GetMacSaltLength(int saltLength) => System.Math.Max(MinMacSaltLength, saltLength);

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

            int maxIterations = Properties.GetInt32(Properties.Pkcs12MaxIterationCount, DefaultMaxIterationCount);
            if (iterations > maxIterations)
                throw new InvalidOperationException($"iteration count {iterations} greater than {maxIterations}");

            return iterations;
        }

        private static byte[] DLEncode(Asn1Encodable asn1Encodable) => asn1Encodable.GetEncoded(Asn1Encodable.DL);
    }
}
