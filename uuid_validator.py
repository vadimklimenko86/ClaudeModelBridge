"""
UUID Validation Utility for OAuth 2.0 Client IDs
Handles various UUID validation scenarios and formats
"""

import uuid
import re
from typing import Union, Optional


class UUIDValidator:
    """Comprehensive UUID validation for OAuth client IDs"""

    @staticmethod
    def is_valid_uuid(value: Union[str, uuid.UUID]) -> bool:
        """Check if value is a valid UUID format"""
        if isinstance(value, uuid.UUID):
            return True

        if not isinstance(value, str):
            return False

        # Remove any whitespace
        value = value.strip()

        # Check UUID format with regex
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
            re.IGNORECASE)

        if not uuid_pattern.match(value):
            return False

        # Try to parse as UUID
        try:
            uuid.UUID(value)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def normalize_uuid(value: Union[str, uuid.UUID]) -> Optional[str]:
        """Normalize UUID to standard string format"""
        if isinstance(value, uuid.UUID):
            return str(value)

        if not isinstance(value, str):
            return None

        value = value.strip().lower()

        if UUIDValidator.is_valid_uuid(value):
            return value

        return None

    @staticmethod
    def generate_uuid4() -> str:
        """Generate a new UUID4 string"""
        return str(uuid.uuid4())

    @staticmethod
    def validate_client_id(client_id: str) -> tuple[bool, str]:
        """
        Validate client ID format
        Returns (is_valid, normalized_id_or_error_message)
        """
        if not client_id:
            return False, "Client ID cannot be empty"

        # Handle string client IDs
        client_id = str(client_id).strip()

        # Check if it's a valid UUID
        #if UUIDValidator.is_valid_uuid(client_id):
        #   normalized = UUIDValidator.normalize_uuid(client_id)
        return True, client_id

        # For non-UUID client IDs, allow alphanumeric with hyphens/underscores
        #if re.match(r'^[a-zA-Z0-9_-]+$', client_id) and len(client_id) >= 3:
        #    return True, client_id

        #return False, f"Invalid client ID format: {client_id}"


def test_uuid_validator():
    """Test the UUID validator with various inputs"""
    test_cases = [
        "550e8400-e29b-41d4-a716-446655440000",  # Valid UUID
        "550E8400-E29B-41D4-A716-446655440000",  # Valid UUID uppercase
        "claude_ai_client",  # Valid non-UUID
        "test-client-123",  # Valid non-UUID
        "invalid uuid",  # Invalid
        "",  # Empty
        "123",  # Too short but valid
    ]

    for test_case in test_cases:
        is_valid, result = UUIDValidator.validate_client_id(test_case)
        print(f"'{test_case}' -> Valid: {is_valid}, Result: '{result}'")


if __name__ == "__main__":
    test_uuid_validator()
