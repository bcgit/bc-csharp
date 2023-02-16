using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal class BcTlsCcmImpl
        : BcTlsAeadCipherImpl
    {
        internal BcTlsCcmImpl(CcmBlockCipher cipher, bool isEncrypting)
            : base(cipher, isEncrypting)
        {
        }

        public override int DoFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
        {
            if (!(m_cipher is CcmBlockCipher ccm))
                throw new InvalidOperationException();

            try
            {
                return ccm.ProcessPacket(input, inputOffset, inputLength, output, outputOffset);
            }
            catch (InvalidCipherTextException e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
            }
        }
    }
}
