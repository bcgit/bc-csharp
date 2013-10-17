using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    internal class DTLSEpoch
    {
        private readonly DTLSReplayWindow replayWindow = new DTLSReplayWindow();
        private readonly int epoch;
        private readonly TlsCipher cipher;

        private long sequence_number = 0;

        public DTLSEpoch(int epoch, TlsCipher cipher)
        {
            if (epoch < 0)
            {
                throw new ArgumentException("'epoch' must be >= 0");
            }
            if (cipher == null)
            {
                throw new ArgumentException("'cipher' cannot be null");
            }

            this.epoch = epoch;
            this.cipher = cipher;
        }

        public long AllocateSequenceNumber()
        {
            // TODO Check for overflow
            return sequence_number++;
        }

        public TlsCipher Cipher
        {
            get
            {
                return cipher;
            }
        }

        public int Epoch
        {
            get
            {
                return epoch;
            }
        }

        public DTLSReplayWindow ReplayWindow
        {
            get
            {
                return replayWindow;
            }
        }

        public long Sequence_number
        {
            get
            {
                return sequence_number;
            }
        }
    }
}