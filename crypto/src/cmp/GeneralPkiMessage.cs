using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class GeneralPKIMessage
    {
        private readonly PkiMessage pkiMessage;

        private static PkiMessage parseBytes(byte[] encoding)
        {
            return PkiMessage.GetInstance(Asn1Object.FromByteArray(encoding));
        }

        public GeneralPKIMessage(PkiMessage pkiMessage)
        {
            this.pkiMessage = pkiMessage;
        }

        public GeneralPKIMessage(byte[] encoding) : this(parseBytes(encoding))
        {
        }

        public PkiHeader Header {
            get {
                return pkiMessage.Header;
            }
        }

        public PkiBody Body
        {
            get
            {
                return pkiMessage.Body;
            }
        }

        public bool HasProtection
        {
            get { return pkiMessage.Protection != null; }
        }

        public PkiMessage ToAsn1Structure()
        {
            return pkiMessage;
        }
    }
}
