class ProxyException(Exception):
    """Base class for exceptions in this module."""
    pass

class CertificateInstallError(ProxyException):
    """Exception raised when the certificate installation fails."""
    pass