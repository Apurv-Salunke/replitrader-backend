from typing import Any, Dict, Optional

class Response:
    """
    A standard response object for API endpoints.
    """
    def __init__(self, success: bool, data: Any = None, message: Optional[str] = None, error_code: Optional[str] = None):
        self.success = success
        self.data = data
        self.message = message
        self.error_code = error_code

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts the Response object to a dictionary suitable for JSON serialization.
        """
        response_dict = {
            "success": self.success,
        }
        if self.data is not None:
            response_dict["data"] = self.data
        if self.message is not None:
            response_dict["message"] = self.message
        if self.error_code is not None:
            response_dict["error_code"] = self.error_code
        return response_dict

def success_response(data: Any = None, message: Optional[str] = "Operation successful") -> Dict[str, Any]:
    """
    Helper function to create a success response dictionary.
    """
    return Response(success=True, data=data, message=message).to_dict()

def error_response(message: str, error_code: Optional[str] = None, data: Any = None) -> Dict[str, Any]:
    """
    Helper function to create an error response dictionary.
    """
    return Response(success=False, message=message, error_code=error_code, data=data).to_dict() 