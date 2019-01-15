using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Crmf
{
    /**
     * An encrypted value padder is used to make sure that prior to a value been
     * encrypted the data is padded to a standard length.
     */
    public interface EncryptedValuePadder
    {
        /**
         * Return a byte array of padded data.
         *
         * @param data the data to be padded.
         * @return a padded byte array containing data.
         */
        byte[] GetPaddedData(byte[] data);

        /**
         * Return a byte array of with padding removed.
         *
         * @param paddedData the data to be padded.
         * @return an array containing the original unpadded data.
         */
        byte[] GetUnpaddedData(byte[] paddedData);
    }
}
