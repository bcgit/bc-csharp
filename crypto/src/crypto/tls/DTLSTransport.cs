using System.IO;
using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class DTLSTransport : DatagramTransport
    {
        private readonly DTLSRecordLayer recordLayer;

        internal DTLSTransport(DTLSRecordLayer recordLayer)
        {
            this.recordLayer = recordLayer;
        }

        public int ReceiveLimit
        {
            get
            {
                return recordLayer.ReceiveLimit;
            }
        }

        public int SendLimit
        {
            get
            {
                return recordLayer.SendLimit;
            }
        }

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            try
            {
                return recordLayer.Receive(buf, off, len, waitMillis);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                recordLayer.Fail(fatalAlert.AlertDescription);
                throw fatalAlert;
            }
            catch (IOException e)
            {
                recordLayer.Fail(AlertDescription.internal_error);
                throw e;
            }
            catch (Exception e)
            {
                recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        public void Send(byte[] buf, int off, int len)
        {
            try
            {
                recordLayer.Send(buf, off, len);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                recordLayer.Fail(fatalAlert.AlertDescription);
                throw fatalAlert;
            }
            catch (IOException e)
            {
                recordLayer.Fail(AlertDescription.internal_error);
                throw e;
            }
            catch (Exception e)
            {
                recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public void Close()
        {
            recordLayer.Close();
        }

        void IDisposable.Dispose()
        {
            Close();
        }
    }
}
