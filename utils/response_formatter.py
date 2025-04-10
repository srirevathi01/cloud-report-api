def format_response(status_code: str, status_message: str, data: dict):
    return {
        "statusCode": status_code,
        "statusMessage": status_message,
        "data": data
    }