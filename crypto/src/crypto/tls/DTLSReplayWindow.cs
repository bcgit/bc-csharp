using System;
namespace Org.BouncyCastle.Crypto.Tls
{
    /**
     * RFC 4347 4.1.2.5 Anti-replay
     * <p/>
     * Support fast rejection of duplicate records by maintaining a sliding receive window
     */
    class DTLSReplayWindow
    {
        private const long VALID_SEQ_MASK = 0x0000FFFFFFFFFFFFL;
        private const long WINDOW_SIZE = 64L;
        private long latestConfirmedSeq = -1;
        private long bitmap = 0;

        /**
         * Check whether a received record with the given sequence number should be rejected as a duplicate.
         *
         * @param seq the 48-bit DTLSPlainText.sequence_number field of a received record.
         * @return true if the record should be discarded without further processing.
         */
        public bool ShouldDiscard(long seq)
        {
            if ((seq & VALID_SEQ_MASK) != seq)
            {
                return true;
            }

            if (seq <= latestConfirmedSeq)
            {
                long diff = latestConfirmedSeq - seq;

                if (diff >= WINDOW_SIZE)
                {
                    return true;
                }
                if ((bitmap & (1L << (int)diff)) != 0)
                {
                    return true;
                }
            }

            return false;
        }

        /**
         * Report that a received record with the given sequence number passed authentication checks.
         *
         * @param seq the 48-bit DTLSPlainText.sequence_number field of an authenticated record.
         */
        public void ReportAuthenticated(long seq)
        {
            if ((seq & VALID_SEQ_MASK) != seq)
            {
                throw new ArgumentException("'seq' out of range");
            }

            if (seq <= latestConfirmedSeq)
            {
                long diff = latestConfirmedSeq - seq;
                if (diff < WINDOW_SIZE)
                {
                    bitmap |= (1L << (int)diff);
                }
            }
            else
            {
                long diff = seq - latestConfirmedSeq;
                if (diff >= WINDOW_SIZE)
                {
                    bitmap = 1;
                }
                else
                {
                    bitmap <<= (int)diff;        // for earlier JDKs
                    bitmap |= 1;
                }
                latestConfirmedSeq = seq;
            }
        }

        /**
         * When a new epoch begins, sequence numbers begin again at 0
         */
        public void Reset()
        {
            latestConfirmedSeq = -1;
            bitmap = 0;
        }
    }

}