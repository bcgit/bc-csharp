using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>Utility class for reencoding PKCS#12 files to definite length.</summary>
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
            Asn1OctetString content = Asn1OctetString.GetInstance(info.Content);
            byte[] contentOctets = content.GetOctets();

            Asn1Object obj = Asn1Object.FromByteArray(contentOctets);

            contentOctets = DLEncode(obj);
            content = new DerOctetString(contentOctets);
            info = new ContentInfo(info.ContentType, content);

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
                    var macDigestAlgorithm = macData.Mac.DigestAlgorithm;
                    byte[] salt = macData.MacSalt.GetOctets();
                    int iterations = macData.Iterations.IntValueExact;
                    byte[] macResult = Pkcs12Store.CalculatePbeMac(macDigestAlgorithm, salt, iterations, passwd,
                        wrongPkcs12Zero: false, data: contentOctets);
                    var mac = new DigestInfo(macDigestAlgorithm, new DerOctetString(macResult));

                    macData = new MacData(mac, macData.MacSalt, macData.Iterations);
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

        private static byte[] DLEncode(Asn1Encodable asn1Encodable) => asn1Encodable.GetEncoded(Asn1Encodable.DL);
    }
}
