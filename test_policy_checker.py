import unittest
from policy_checker import checkIAMPolicy 


class TestCheckIAMPolicy(unittest.TestCase):

    def test_valid_policy(self):
        """Test a valid policy with specific resources"""
        json_data = """
        {
            "PolicyName": "ValidPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:ListBucket",
                        "Resource": "arn:aws:s3:::example_bucket"
                    }
                ]
            }
        }
        """
        self.assertTrue(checkIAMPolicy(json_data))

    def test_policy_with_asterisk(self):
        """Test a policy with a single asterisk"""
        json_data = """
        {
            "PolicyName": "InvalidPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "*"
                    }
                ]
            }
        }
        """
        self.assertFalse(checkIAMPolicy(json_data))

    def test_policy_missing_required_fields(self):
        """Test a policy missing 'PolicyName' """
        json_data = """
        {
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:ListBucket",
                        "Resource": "arn:aws:s3:::example_bucket"
                    }
                ]
            }
        }
        """
        self.assertFalse(checkIAMPolicy(json_data))

    def test_invalid_json_format(self):
        """Test with an invalid JSON format"""
        json_data = """
        { This is not a valid JSON string }
        """
        self.assertFalse(checkIAMPolicy(json_data))

    def test_empty_policy(self):
        """Test an empty policy document"""
        json_data = "{}"
        self.assertFalse(checkIAMPolicy(json_data))

    def test_policy_with_list_resource_including_asterisk(self):
        """Test a policy where the Resource field is a list including an asterisk"""
        json_data = """
        {
            "PolicyName": "ListResourcePolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:ListBucket",
                        "Resource": ["arn:aws:s3:::example_bucket", "*"]
                    }
                ]
            }
        }
        """
        self.assertFalse(checkIAMPolicy(json_data))

if __name__ == '__main__':
    unittest.main()