using System;
namespace Org.BouncyCastle.Crypto.Tls
{

    /**
     * RFC 5764 4.1.1
     */
    public class UseSRTPData
    {
        private int[] protectionProfiles;
        private byte[] mki;

        /**
         * @param protectionProfiles see {@link SRTPProtectionProfile} for valid constants.
         * @param mki                valid lengths from 0 to 255.
         */
        public UseSRTPData(int[] protectionProfiles, byte[] mki)
        {

            if (protectionProfiles == null || protectionProfiles.Length < 1
                || protectionProfiles.Length >= (1 << 15))
            {
                throw new ArgumentException(
                    "'protectionProfiles' must have length from 1 to (2^15 - 1)");
            }

            if (mki == null)
            {
                mki = TlsUtilities.EMPTY_BYTES;
            }
            else if (mki.Length > 255)
            {
                throw new ArgumentException("'mki' cannot be longer than 255 bytes");
            }

            this.protectionProfiles = protectionProfiles;
            this.mki = mki;
        }

        /**
         * @return see {@link SRTPProtectionProfile} for valid constants.
         */
        public int[] ProtectionProfiles
        {
            get
            {
                return protectionProfiles;
            }
        }

        /**
         * @return valid lengths from 0 to 255.
         */
        public byte[] Mki
        {
            get
            {
                return mki;
            }
        }
    }

}