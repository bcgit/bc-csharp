using System;

namespace Org.BouncyCastle.Pkix
{
#if !PORTABLE
    [Serializable]
#endif
    public class PkixNameConstraintValidatorException
        : Exception
    {
        public PkixNameConstraintValidatorException(String msg)
            : base(msg)
        {
        }
    }
}
