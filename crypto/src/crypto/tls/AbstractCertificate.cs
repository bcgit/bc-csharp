using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class AbstractCertificate
    {
        public abstract void Encode(Stream output);

        /**
         * @return <code>true</code> if this certificate chain contains no certificates, or
         *         <code>false</code> otherwise.
         */
        public virtual bool IsEmpty
        {
             get => false;
        }

        public abstract SubjectPublicKeyInfo SubjectPublicKeyInfo();
    }
}
