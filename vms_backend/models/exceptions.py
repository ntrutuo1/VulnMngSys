class BusinessException(Exception):
    """Base class for all business logic exceptions."""
    pass


class NotFoundException(BusinessException):
    """Exception raised when a requested resource is not found."""
    pass


class ValidationException(BusinessException):
    """Exception raised when inputs fail business validation rules."""
    pass
