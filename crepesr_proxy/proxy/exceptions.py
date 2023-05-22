class ProxyException(Exception):
    """Base class for exceptions in this module."""
    pass

class CertificateInstallError(ProxyException):
    """Exception raised when the certificate installation fails."""
    pass

class SetSystemProxyError(ProxyException):
    """Exception raised when the system proxy cannot be set."""
    pass

class UnsetSystemProxyError(ProxyException):
    """Exception raised when the system proxy cannot be unset."""
    pass
