import json

def checkIAMPolicy (json_data: str) -> bool:
    """
    Check if the input JSON data is a valid AWS::IAM::Role Policy
    The function checks if the 'Resource' field contains a single asterisk ('*') and returns False if true, and True in any other case
    """
    
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON input: {e}")
        return False

    # Check if 'PolicyDocument' and 'PolicyName' fields are present
    if not all(key in data for key in ("PolicyDocument", "PolicyName")):
        return False

    # Navigate safely through potentially missing keys
    statements = data.get("PolicyDocument", {}).get("Statement", [])
    if not statements:
        return False

    for statement in statements:
        # Assuming 'Resource' can be a string or a list, handle both cases
        resources = statement.get("Resource")
        if isinstance(resources, list):
            if "*" in resources:
                return False
        elif resources == "*":
            return False

    return True