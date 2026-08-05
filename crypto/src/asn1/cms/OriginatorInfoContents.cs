namespace Org.BouncyCastle.Asn1.Cms
{
    internal static class OriginatorInfoContents
    {
        internal const int None = 0;
        internal const int V2AttributeCertificate = 1;
        internal const int Other = 2;

        internal static int Classify(OriginatorInfo originatorInfo)
        {
            if (originatorInfo != null)
            {
                var crls = originatorInfo.Crls;
                if (crls != null)
                {
                    foreach (var element in crls)
                    {
                        // RevocationInfoChoice.other
                        var tagged = Asn1TaggedObject.GetContextOptional(element, 1);
                        if (tagged != null)
                            return Other;
                    }
                }

                var certs = originatorInfo.Certificates;
                if (certs != null)
                {
                    bool anyV2AttrCerts = false;

                    foreach (var element in certs)
                    {
                        var tagged = Asn1TaggedObject.GetContextOptional(element);
                        if (tagged != null)
                        {
                            // CertificateChoices.other
                            if (tagged.HasTagNo(3))
                                return Other;

                            // CertificateChoices.v2AttrCert
                            anyV2AttrCerts = anyV2AttrCerts || tagged.HasTagNo(2);
                        }
                    }

                    if (anyV2AttrCerts)
                        return V2AttributeCertificate;
                }
            }

            return None;
        }
    }
}
